from __future__ import annotations

import pytest

import agent_firewall.engine as engine_module
from agent_firewall.engine import SecurityEngine
from agent_firewall.models import Decision
from agent_firewall.normalize import normalize


def test_unknown_tool_blocked_by_authorization(engine: SecurityEngine) -> None:
    d = engine.evaluate(normalize("Frobnicate", {"x": 1}))
    assert d.decision is Decision.BLOCK
    assert "authorization.unknown_tool" in d.matched_rules
    assert "authorization" in d.explanation.lower()


def test_sensitive_file_read_denied(engine: SecurityEngine) -> None:
    d = engine.evaluate(normalize("Read", {"file_path": ".env"}))
    assert d.decision is Decision.BLOCK
    assert "block-protected-credentials" in d.matched_policies


def test_path_traversal_requires_approval(engine: SecurityEngine) -> None:
    d = engine.evaluate(normalize("Read", {"file_path": "../secrets.txt"}))
    assert d.decision is Decision.ASK
    assert "fs.path_traversal" in d.matched_rules


def test_benign_read_allowed(engine: SecurityEngine) -> None:
    d = engine.evaluate(normalize("Read", {"file_path": "README.md"}))
    assert d.decision is Decision.ALLOW
    assert d.risk_score == 0


def test_destructive_command_blocked_by_risk(engine: SecurityEngine) -> None:
    d = engine.evaluate(normalize("Bash", {"command": "rm -rf /"}))
    assert d.decision is Decision.BLOCK
    assert d.risk_score >= 85
    assert "block-critical-risk" in d.matched_policies


def test_detector_error_fails_closed_not_open(
    engine: SecurityEngine, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_command: str):
        raise RuntimeError("detector crash")

    monkeypatch.setattr(engine_module, "inspect_command", boom)
    d = engine.evaluate(normalize("Bash", {"command": "echo hi"}))
    # A crashing detector must NOT silently allow; it is treated as uncertain.
    assert "engine.detector_error" in d.matched_rules
    assert d.decision is not Decision.ALLOW
