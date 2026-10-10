"""Shared pytest fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_firewall.engine import SecurityEngine
from agent_firewall.policies import PolicyDocument, load_policy_document

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"


@pytest.fixture(scope="session")
def default_doc() -> PolicyDocument:
    return load_policy_document(DEFAULT_POLICY)


@pytest.fixture()
def engine(default_doc: PolicyDocument) -> SecurityEngine:
    return SecurityEngine(default_doc)


@pytest.fixture()
def audit_path(tmp_path: Path) -> Path:
    return tmp_path / "audit.jsonl"
