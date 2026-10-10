from __future__ import annotations

import pytest

from agent_firewall.policies.loader import (
    PolicyLoadError,
    load_policy_document_from_string,
)
from agent_firewall.policies.schema import Effect


def test_valid_minimal_document() -> None:
    doc = load_policy_document_from_string("version: 1\npolicies: []\n")
    assert doc.version == 1
    assert doc.default_effect is Effect.ALLOW
    assert doc.policies == []


def test_extra_keys_are_rejected() -> None:
    with pytest.raises(PolicyLoadError):
        load_policy_document_from_string(
            "policies:\n  - id: x\n    effect: deny\n    bogus_key: 1\n"
        )


def test_duplicate_ids_rejected() -> None:
    raw = (
        "policies:\n"
        "  - id: dup\n    effect: allow\n"
        "  - id: dup\n    effect: deny\n"
    )
    with pytest.raises(PolicyLoadError, match="duplicate policy id"):
        load_policy_document_from_string(raw)


def test_invalid_risk_threshold_rejected() -> None:
    with pytest.raises(PolicyLoadError):
        load_policy_document_from_string(
            "policies:\n  - id: x\n    effect: approval\n    risk_threshold: 150\n"
        )


def test_invalid_effect_rejected() -> None:
    with pytest.raises(PolicyLoadError):
        load_policy_document_from_string(
            "policies:\n  - id: x\n    effect: maybe\n"
        )


def test_non_mapping_document_rejected() -> None:
    with pytest.raises(PolicyLoadError):
        load_policy_document_from_string("- just\n- a\n- list\n")


def test_pure_risk_gate_detection() -> None:
    doc = load_policy_document_from_string(
        "policies:\n  - id: gate\n    effect: deny\n    risk_threshold: 85\n"
    )
    assert doc.policies[0].is_pure_risk_gate() is True
