from __future__ import annotations

from agent_firewall.models import ActionType, Decision, NormalizedRequest
from agent_firewall.policies import evaluate_policies
from agent_firewall.policies.loader import load_policy_document_from_string


def _req(tool: str = "Read", resource: str | None = None, **kw) -> NormalizedRequest:
    return NormalizedRequest(tool_name=tool, resource=resource, **kw)


def test_deny_beats_allow() -> None:
    doc = load_policy_document_from_string(
        "policies:\n"
        "  - id: a\n    effect: allow\n    tools: [Read]\n"
        "  - id: d\n    effect: deny\n    tools: [Read]\n"
    )
    out = evaluate_policies(doc, _req("Read"), risk_score=0)
    assert out.decision is Decision.BLOCK
    assert out.matched_policies == ["d"]


def test_approval_beats_allow_but_not_deny() -> None:
    doc = load_policy_document_from_string(
        "policies:\n"
        "  - id: a\n    effect: allow\n    tools: [Read]\n"
        "  - id: p\n    effect: approval\n    tools: [Read]\n"
    )
    out = evaluate_policies(doc, _req("Read"), risk_score=0)
    assert out.decision is Decision.ASK


def test_low_risk_cannot_override_deny() -> None:
    doc = load_policy_document_from_string(
        "policies:\n  - id: d\n    effect: deny\n    tools: [Bash]\n"
    )
    out = evaluate_policies(doc, _req("Bash"), risk_score=0)
    assert out.decision is Decision.BLOCK


def test_risk_gate_triggers_at_threshold() -> None:
    doc = load_policy_document_from_string(
        "policies:\n  - id: gate\n    effect: approval\n    risk_threshold: 70\n"
    )
    assert evaluate_policies(doc, _req(), 69).decision is Decision.ALLOW  # default
    assert evaluate_policies(doc, _req(), 70).decision is Decision.ASK


def test_default_effect_applies_when_nothing_matches() -> None:
    doc = load_policy_document_from_string(
        "default_effect: deny\npolicies:\n  - id: a\n    effect: allow\n    tools: [Write]\n"
    )
    out = evaluate_policies(doc, _req("Read"), 0)
    assert out.decision is Decision.BLOCK


def test_glob_resource_matching_normalises_backslashes() -> None:
    doc = load_policy_document_from_string(
        "policies:\n  - id: d\n    effect: deny\n    resource_patterns: ['**/.env']\n"
    )
    req = _req("Read", resource="project\\config\\.env")
    assert evaluate_policies(doc, req, 0).decision is Decision.BLOCK


def test_action_type_selector() -> None:
    doc = load_policy_document_from_string(
        "policies:\n  - id: w\n    effect: deny\n    action_types: [write]\n"
    )
    r = _req("Write", action_type=ActionType.WRITE)
    assert evaluate_policies(doc, r, 0).decision is Decision.BLOCK
    r2 = _req("Read", action_type=ActionType.READ)
    assert evaluate_policies(doc, r2, 0).decision is Decision.ALLOW


def test_determinism_same_inputs_same_output() -> None:
    doc = load_policy_document_from_string(
        "policies:\n"
        "  - id: a\n    effect: allow\n    tools: [Read]\n"
        "  - id: p\n    effect: approval\n    tools: [Read]\n"
        "  - id: d\n    effect: deny\n    tools: [Read]\n"
    )
    first = evaluate_policies(doc, _req("Read"), 10)
    for _ in range(50):
        assert evaluate_policies(doc, _req("Read"), 10).decision is first.decision
