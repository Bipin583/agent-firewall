"""API integration tests (optional [api] extra).

Skipped automatically if FastAPI/SQLAlchemy are not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("sqlalchemy")
pytest.importorskip("aiosqlite")

from fastapi.testclient import TestClient  # noqa: E402

from agent_firewall.api import create_app  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_POLICY = REPO_ROOT / "policies" / "default.yaml"
TOKEN = "test-token-123"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AGENT_FIREWALL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    monkeypatch.setenv("AGENT_FIREWALL_POLICY_FILE", str(DEFAULT_POLICY))
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    app = create_app(policy_file=str(DEFAULT_POLICY), db_url=db_url, token=TOKEN)
    with TestClient(app) as c:
        yield c


def test_healthz_no_auth(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["auth_configured"] is True
    assert body["policies_loaded"] >= 1


def test_evaluate_requires_token(client: TestClient) -> None:
    assert client.post("/v1/evaluate", json={"tool_name": "Read"}).status_code == 401
    bad = client.post(
        "/v1/evaluate", json={"tool_name": "Read"}, headers={"Authorization": "Bearer nope"}
    )
    assert bad.status_code == 403


def test_evaluate_benign_allow(client: TestClient) -> None:
    resp = client.post(
        "/v1/evaluate",
        json={"tool_name": "Read", "tool_input": {"file_path": "README.md"}},
        headers=AUTH,
    )
    assert resp.status_code == 200
    assert resp.json()["decision"] == "allow"


def test_evaluate_dangerous_block_and_persist(client: TestClient) -> None:
    resp = client.post(
        "/v1/evaluate",
        json={"tool_name": "Bash", "tool_input": {"command": "rm -rf /"}},
        headers=AUTH,
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "block"
    assert body["risk_score"] >= 85

    listed = client.get("/v1/decisions", headers=AUTH).json()
    assert listed["count"] >= 1
    assert any(d["decision"] == "block" for d in listed["decisions"])


def test_persisted_summary_scrubs_secrets(client: TestClient) -> None:
    # A secret embedded in the inspected resource must be masked in what we store.
    key = "AKIAIOSFODNN7EXAMPLE"
    client.post(
        "/v1/evaluate",
        json={"tool_name": "Bash", "tool_input": {"command": f"echo {key}"}},
        headers=AUTH,
    )
    listed = client.get("/v1/decisions", headers=AUTH).json()
    assert all(key not in d["redacted_summary"] for d in listed["decisions"])


def test_audit_verify_ok(client: TestClient) -> None:
    client.post(
        "/v1/evaluate",
        json={"tool_name": "Read", "tool_input": {"file_path": "a.txt"}},
        headers=AUTH,
    )
    result = client.get("/v1/audit/verify", headers=AUTH).json()
    assert result["ok"] is True
    assert result["total_events"] >= 1


def test_policy_validate(client: TestClient) -> None:
    good = client.post(
        "/v1/policy/validate", json={"document": DEFAULT_POLICY.read_text()}, headers=AUTH
    )
    assert good.json()["ok"] is True
    bad = client.post(
        "/v1/policy/validate", json={"document": "version: 1\nbogus_key: 7"}, headers=AUTH
    )
    assert bad.json()["ok"] is False


def test_missing_token_config_is_503(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_FIREWALL_AUDIT_LOG", str(tmp_path / "audit.jsonl"))
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"
    app = create_app(policy_file=str(DEFAULT_POLICY), db_url=db_url, token="")
    with TestClient(app) as c:
        resp = c.post("/v1/evaluate", json={"tool_name": "Read"}, headers=AUTH)
        assert resp.status_code == 503
