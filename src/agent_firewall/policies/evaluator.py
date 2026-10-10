"""Deterministic policy matching and precedence resolution.

This module answers one question: *given a request and (optionally) a risk score,
which policies match and what effect do they jointly imply?*

Precedence (Part 7), applied in order and documented in docs/policy-engine.md:
  1. Authorization is handled upstream in the engine, not here.
  2. Any matching ``deny`` policy => BLOCK. Deny always wins; a low risk score
     can never override it.
  3. Any matching ``approval`` policy (selector match, or risk_threshold crossed)
     => ASK, unless a deny already fired.
  4. Otherwise, if any ``allow`` policy matches, or the document default is allow
     => ALLOW.
  5. If nothing matches and default is deny/approval, that effect applies.

Matching never executes anything and never calls an LLM.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch

from ..models import Decision, NormalizedRequest
from .schema import Effect, Policy, PolicyDocument


@dataclass(frozen=True)
class PolicyOutcome:
    decision: Decision
    matched_policies: list[str]
    reasons: list[str]


def _glob_any(value: str | None, patterns: list[str]) -> bool:
    if not patterns:
        return True  # no constraint on this dimension
    if value is None:
        return False
    # Match against the raw value and a forward-slash normalised copy so that
    # Windows backslashes do not defeat posix-style patterns like **/.env.
    normalised = value.replace("\\", "/")
    return any(fnmatch(value, p) or fnmatch(normalised, p) for p in patterns)


def _list_any(value: str | None, allowed: list[str]) -> bool:
    if not allowed:
        return True
    return value is not None and value in allowed


def policy_matches(policy: Policy, req: NormalizedRequest, risk_score: int | None) -> bool:
    """Return True if every populated selector of ``policy`` matches ``req``."""
    if policy.is_pure_risk_gate():
        # Risk-only approval gate: matches purely on the threshold.
        return risk_score is not None and risk_score >= (policy.risk_threshold or 0)

    if not _list_any(req.tool_name, policy.tools):
        return False
    if not _list_any(req.agent_id, policy.agents):
        return False
    if not _list_any(req.action_type.value, policy.action_types):
        return False
    if not _list_any(req.environment, policy.environments):
        return False
    if not _glob_any(req.resource, policy.resource_patterns):
        return False

    destination = req.tool_args.get("destination") or req.tool_args.get("url")
    if policy.destination_patterns and not _glob_any(
        destination if isinstance(destination, str) else None, policy.destination_patterns
    ):
        return False

    # A risk_threshold on any effect requires the score to reach it.
    return policy.risk_threshold is None or (
        risk_score is not None and risk_score >= policy.risk_threshold
    )


def evaluate_policies(
    doc: PolicyDocument, req: NormalizedRequest, risk_score: int | None
) -> PolicyOutcome:
    """Resolve all matching policies into a single deterministic decision."""
    denies: list[Policy] = []
    approvals: list[Policy] = []
    allows: list[Policy] = []

    for policy in doc.enabled_policies():
        if policy_matches(policy, req, risk_score):
            if policy.effect is Effect.DENY:
                denies.append(policy)
            elif policy.effect is Effect.APPROVAL:
                approvals.append(policy)
            else:
                allows.append(policy)

    # Precedence: deny > approval > allow. Deterministic because the policy list
    # is ordered and we never short-circuit before collecting everything.
    if denies:
        return PolicyOutcome(
            decision=Decision.BLOCK,
            matched_policies=[p.id for p in denies],
            reasons=[f"deny policy '{p.id}' matched" for p in denies],
        )
    if approvals:
        return PolicyOutcome(
            decision=Decision.ASK,
            matched_policies=[p.id for p in approvals],
            reasons=[f"approval policy '{p.id}' matched" for p in approvals],
        )
    if allows:
        return PolicyOutcome(
            decision=Decision.ALLOW,
            matched_policies=[p.id for p in allows],
            reasons=[f"allow policy '{p.id}' matched" for p in allows],
        )

    # Nothing matched -> fall back to the document default.
    default_map = {
        Effect.DENY: Decision.BLOCK,
        Effect.APPROVAL: Decision.ASK,
        Effect.ALLOW: Decision.ALLOW,
    }
    return PolicyOutcome(
        decision=default_map[doc.default_effect],
        matched_policies=[],
        reasons=[f"no policy matched; document default is '{doc.default_effect.value}'"],
    )
