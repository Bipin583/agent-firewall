"""Runtime configuration for Agent Firewall.

Loaded from environment variables (optionally via a .env file that scripts may
source). The *hook path* only needs the fields in the "core" group below; the API
fields are read lazily so the hook never pulls in DB/web dependencies.

Design note: configuration is deliberately simple (no pydantic-settings) so the
hook starts fast and has a minimal dependency surface.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent
# repo root = .../ (src/agent_firewall -> up 2)
REPO_ROOT = PACKAGE_DIR.parent.parent


def _bundled_default_policy() -> Path:
    return REPO_ROOT / "policies" / "default.yaml"


@dataclass(frozen=True)
class CoreConfig:
    """Everything the local decision path needs. No network, no database."""

    policy_file: Path
    audit_log: Path
    environment: str
    on_error: str  # "ask" | "deny" | "allow"
    project_root: Path | None

    @staticmethod
    def from_env(cwd: str | None = None) -> CoreConfig:
        policy_file = os.environ.get("AGENT_FIREWALL_POLICY_FILE")
        audit_log = os.environ.get("AGENT_FIREWALL_AUDIT_LOG", ".agent_firewall/audit.jsonl")
        on_error = os.environ.get("AGENT_FIREWALL_ON_ERROR", "ask").strip().lower()
        if on_error not in {"ask", "deny", "allow"}:
            on_error = "ask"

        base = Path(cwd).resolve() if cwd else Path.cwd()

        policy_path = Path(policy_file).expanduser() if policy_file else _bundled_default_policy()
        if not policy_path.is_absolute():
            policy_path = (base / policy_path).resolve()

        audit_path = Path(audit_log).expanduser()
        if not audit_path.is_absolute():
            audit_path = (base / audit_path).resolve()

        pr_env = os.environ.get("AGENT_FIREWALL_PROJECT_ROOT")
        project_root = Path(pr_env).expanduser().resolve() if pr_env else base

        return CoreConfig(
            policy_file=policy_path,
            audit_log=audit_path,
            environment=os.environ.get("AGENT_FIREWALL_ENV", "development"),
            on_error=on_error,
            project_root=project_root,
        )


def api_db_url() -> str:
    return os.environ.get(
        "AGENT_FIREWALL_DB_URL", "sqlite+aiosqlite:///./data/agent_firewall.db"
    )


def api_token() -> str | None:
    return os.environ.get("AGENT_FIREWALL_API_TOKEN")
