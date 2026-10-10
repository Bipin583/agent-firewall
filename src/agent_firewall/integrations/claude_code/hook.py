"""Claude Code PreToolUse hook adapter.

Translates the Claude Code hook protocol (verified against the official docs on
2026-10-09) to/from the vendor-neutral engine, and back.

Hook protocol facts this adapter relies on (documented in docs/hook-integration.md):
  * Input: a JSON object on stdin with ``hook_event_name``, ``tool_name``,
    ``tool_input``, ``session_id``, ``cwd`` (and more we don't require).
  * Output: exit 0 and print a JSON object whose ``hookSpecificOutput`` carries
    ``hookEventName: "PreToolUse"`` and ``permissionDecision`` in
    {allow, deny, ask}, with ``permissionDecisionReason``.
  * stdout MUST contain only that JSON object; everything else goes to stderr.
  * Exit 2 also blocks, but we prefer the explicit JSON ``deny`` for clarity.

Decision mapping:
  BLOCK -> permissionDecision "deny"
  ASK   -> permissionDecision "ask"
  ALLOW -> defer to Claude Code's native permission flow (no decision emitted),
           so the firewall never *disables* native controls. Set
           AGENT_FIREWALL_EMIT_ALLOW=1 to emit an explicit "allow" instead.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from ...audit import AuditWriter
from ...config import CoreConfig
from ...engine import SecurityEngine
from ...models import Decision, SecurityDecision, TrustLevel
from ...normalize import normalize
from ...policies import PolicyLoadError, load_policy_document

HOOK_EVENT = "PreToolUse"


def _log(msg: str) -> None:
    """Diagnostics go to stderr only; stdout is reserved for the JSON response."""
    print(f"[agent-firewall] {msg}", file=sys.stderr)


def _emit(hook_output: dict[str, Any] | None) -> None:
    if hook_output is None:
        return  # defer: emit nothing, let native flow proceed
    sys.stdout.write(json.dumps(hook_output))
    sys.stdout.flush()


def _response_for(decision: SecurityDecision, emit_allow: bool) -> dict[str, Any] | None:
    mapping = {
        Decision.BLOCK: "deny",
        Decision.ASK: "ask",
        Decision.ALLOW: "allow",
    }
    perm = mapping[decision.decision]
    if decision.decision is Decision.ALLOW and not emit_allow:
        return None
    return {
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": perm,
            "permissionDecisionReason": decision.explanation,
        }
    }


def _error_response(on_error: str, reason: str) -> dict[str, Any] | None:
    """Build the response used when evaluation itself fails or input is unusable."""
    if on_error == "allow":
        return None  # defer to native flow
    perm = "deny" if on_error == "deny" else "ask"
    return {
        "hookSpecificOutput": {
            "hookEventName": HOOK_EVENT,
            "permissionDecision": perm,
            "permissionDecisionReason": f"Agent Firewall: {reason}",
        }
    }


def evaluate_payload(
    payload: dict[str, Any],
) -> tuple[SecurityDecision | None, dict[str, Any] | None]:
    """Pure core: payload -> (decision, hook_output). Used directly by tests.

    Raises nothing for a well-formed payload; policy/engine errors propagate to the
    caller (``main``) which applies the on-error policy.
    """
    tool_name = payload.get("tool_name")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_name, str) or not isinstance(tool_input, dict):
        raise ValueError("payload missing a string tool_name / object tool_input")

    cwd = payload.get("cwd")
    config = CoreConfig.from_env(cwd=cwd)
    doc = load_policy_document(config.policy_file)
    engine = SecurityEngine(doc)

    req = normalize(
        tool_name,
        tool_input,
        session_id=payload.get("session_id"),
        agent_id=payload.get("agent_id"),
        cwd=cwd,
        project_root=str(config.project_root) if config.project_root else None,
        environment=config.environment,
        content_trust=TrustLevel.UNKNOWN,
    )
    decision = engine.evaluate(req)

    # Best-effort audit; a failure here must not change the security decision.
    try:
        AuditWriter(config.audit_log).record(req, decision)
    except Exception as exc:  # noqa: BLE001
        _log(f"audit write failed (decision still enforced): {exc}")

    emit_allow = os.environ.get("AGENT_FIREWALL_EMIT_ALLOW") == "1"
    return decision, _response_for(decision, emit_allow)


def main(argv: list[str] | None = None) -> int:
    raw = sys.stdin.read()
    on_error = os.environ.get("AGENT_FIREWALL_ON_ERROR", "ask").strip().lower()
    if on_error not in {"ask", "deny", "allow"}:
        on_error = "ask"

    try:
        payload = json.loads(raw) if raw.strip() else {}
    except ValueError as exc:
        _log(f"could not parse hook input as JSON: {exc}")
        _emit(_error_response(on_error, "unparseable hook input"))
        return 0

    event = payload.get("hook_event_name")
    if event not in (None, HOOK_EVENT):
        # Not our event; do nothing and defer.
        _log(f"ignoring unexpected hook event: {event}")
        return 0

    try:
        decision, hook_output = evaluate_payload(payload)
    except PolicyLoadError as exc:
        _log(f"policy load failed: {exc}")
        _emit(_error_response(on_error, f"policy load failed: {exc}"))
        return 0
    except Exception as exc:  # noqa: BLE001
        _log(f"evaluation error: {exc}")
        _emit(_error_response(on_error, f"evaluation error: {type(exc).__name__}"))
        return 0

    if decision is not None:
        _log(f"{decision.decision.value} risk={decision.risk_score} :: {decision.explanation}")
    _emit(hook_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
