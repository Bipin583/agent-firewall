"""The core security engine.

Public contract (Part 6):

    engine = SecurityEngine(policy_doc, authorization=..., config=...)
    decision = engine.evaluate(request)   # NormalizedRequest -> SecurityDecision

The engine NEVER executes the requested tool. It only evaluates. The order of
operations and the precedence rules are the security-critical part:

    1. Authorization (fail-closed). Unauthorized -> BLOCK immediately.
    2. Run deterministic detectors appropriate to the action type.
    3. Compute an explainable risk score from the findings.
    4. Evaluate declarative policies, passing the risk score in.
    5. Combine: a policy BLOCK always wins; otherwise policy ASK/ALLOW stands.
       A high risk score never silently overrides a deny, and a low score never
       rescues a denied/unauthorized request.
"""

from __future__ import annotations

from .authorization import DEFAULT_AUTHORIZATION, AuthorizationPolicy
from .detection import (
    inspect_command,
    inspect_path,
    inspect_transfer,
    scan_content,
    scan_text,
)
from .models import (
    ActionType,
    Decision,
    NormalizedRequest,
    RiskLevel,
    SecurityDecision,
    SecurityFinding,
    Severity,
    TrustLevel,
)
from .policies import PolicyDocument, evaluate_policies
from .risk import score_request

_DESTRUCTIVE_RULES = {
    "cmd.rm_rf_root",
    "cmd.rm_rf_generic",
    "cmd.disk_format",
    "cmd.fork_bomb",
    "cmd.db_drop",
}


class SecurityEngine:
    def __init__(
        self,
        policy_doc: PolicyDocument,
        authorization: AuthorizationPolicy = DEFAULT_AUTHORIZATION,
    ) -> None:
        self._policies = policy_doc
        self._authz = authorization

    # -- detector orchestration ------------------------------------------------
    def _gather_findings(self, req: NormalizedRequest) -> list[SecurityFinding]:
        findings: list[SecurityFinding] = []
        args = req.tool_args

        if req.action_type is ActionType.EXECUTE:
            command = args.get("command")
            if isinstance(command, str):
                findings += inspect_command(command)
                findings += scan_text(command, source="command")

        elif req.action_type in (ActionType.READ, ActionType.WRITE):
            if req.resource:
                action = "write" if req.action_type is ActionType.WRITE else "read"
                findings += inspect_path(req.resource, action=action, project_root=req.project_root)
            # Writing content that contains secrets is itself notable.
            for key in ("content", "new_string"):
                val = args.get(key)
                if isinstance(val, str):
                    findings += scan_text(val, source=f"{key}")

        elif req.action_type is ActionType.NETWORK:
            findings += inspect_transfer(req)

        # Prompt-injection indicators on any untrusted free-text argument.
        if req.content_trust in (TrustLevel.EXTERNAL_DOCUMENT, TrustLevel.TOOL_OUTPUT):
            for val in args.values():
                if isinstance(val, str):
                    findings += scan_content(val, trust=req.content_trust)

        return findings

    def _context_flags(
        self, req: NormalizedRequest, findings: list[SecurityFinding]
    ) -> dict[str, bool]:
        rule_ids = {f.rule_id for f in findings}
        destructive = bool(rule_ids & _DESTRUCTIVE_RULES)
        external_transfer = req.action_type is ActionType.NETWORK and any(
            k in req.tool_args for k in ("url", "destination", "endpoint")
        )
        untrusted = req.content_trust in (TrustLevel.EXTERNAL_DOCUMENT, TrustLevel.TOOL_OUTPUT)
        return {
            "destructive_action": destructive,
            "external_transfer": external_transfer,
            "untrusted_provenance": untrusted,
        }

    # -- public API ------------------------------------------------------------
    def evaluate(self, req: NormalizedRequest) -> SecurityDecision:
        # 1. Authorization (fail-closed).
        authz = self._authz.check(req)
        if not authz.authorized:
            findings = authz.findings
            score, level, factors = score_request(findings)
            return SecurityDecision(
                request_id=req.request_id,
                decision=Decision.BLOCK,
                risk_score=max(score, 50),  # an authz failure is inherently notable
                risk_level=level,
                matched_policies=[],
                matched_rules=[f.rule_id for f in findings],
                findings=findings,
                risk_factors=factors,
                explanation=f"Blocked by authorization layer: {authz.reason}.",
            )

        # 2 + 3. Detectors and risk.
        findings = list(authz.findings)
        try:
            findings += self._gather_findings(req)
        except Exception as exc:  # a detector bug must not fail-open
            findings.append(
                SecurityFinding(
                    rule_id="engine.detector_error",
                    category="authorization",
                    severity=Severity.MEDIUM,
                    message=(
                        "A detector raised an error; treating request as "
                        f"uncertain: {type(exc).__name__}"
                    ),
                    inferred=True,
                )
            )
        score, level, factors = score_request(
            findings, context_flags=self._context_flags(req, findings)
        )

        # 4. Policies (risk-aware).
        outcome = evaluate_policies(self._policies, req, score)

        # 5. Combine. Policy decision already encodes deny > approval > allow.
        decision = outcome.decision
        reasons = list(outcome.reasons)

        explanation = self._explain(decision, score, level, reasons, findings)
        return SecurityDecision(
            request_id=req.request_id,
            decision=decision,
            risk_score=score,
            risk_level=level,
            matched_policies=outcome.matched_policies,
            matched_rules=[f.rule_id for f in findings],
            findings=findings,
            risk_factors=factors,
            explanation=explanation,
        )

    @staticmethod
    def _explain(
        decision: Decision,
        score: int,
        level: RiskLevel,
        reasons: list[str],
        findings: list[SecurityFinding],
    ) -> str:
        head = {
            Decision.ALLOW: "Allowed.",
            Decision.BLOCK: "Blocked.",
            Decision.ASK: "Approval required.",
        }[decision]
        parts = [head, f"Risk {score}/100 ({level.value})."]
        if reasons:
            parts.append("Policy: " + "; ".join(reasons) + ".")
        top = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)][:3]
        if top:
            parts.append("Findings: " + "; ".join(f.message for f in top) + ".")
        return " ".join(parts)


def evaluate_request(
    req: NormalizedRequest,
    policy_doc: PolicyDocument,
    authorization: AuthorizationPolicy = DEFAULT_AUTHORIZATION,
) -> SecurityDecision:
    """Convenience wrapper matching the Part 6 interface name."""
    return SecurityEngine(policy_doc, authorization).evaluate(req)
