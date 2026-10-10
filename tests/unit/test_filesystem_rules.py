from __future__ import annotations

from agent_firewall.detection.filesystem_rules import (
    has_traversal,
    inspect_path,
    is_outside_project,
    matches_sensitive,
)


def _ids(path: str, action: str = "read", root: str | None = None) -> set[str]:
    return {f.rule_id for f in inspect_path(path, action=action, project_root=root)}


def test_sensitive_patterns() -> None:
    assert matches_sensitive(".env")
    assert matches_sensitive("config/.env.production")
    assert matches_sensitive("deploy/service-account-key.json")
    assert matches_sensitive("keys/server.pem")
    assert matches_sensitive("home/.ssh/id_rsa")
    assert matches_sensitive("src/app.py") is None


def test_traversal_detection() -> None:
    assert has_traversal("../secrets.txt")
    assert has_traversal("a/b/../../../etc/passwd")
    assert not has_traversal("a/b/c.txt")


def test_env_read_flagged_sensitive() -> None:
    assert "fs.sensitive_file" in _ids(".env")


def test_write_to_sensitive_is_present() -> None:
    findings = inspect_path(".env", action="write", project_root=None)
    sev = next(f for f in findings if f.rule_id == "fs.sensitive_file").severity.value
    assert sev == "critical"


def test_outside_project_boundary() -> None:
    root = "/home/user/project"
    assert is_outside_project("/etc/passwd", root)
    assert is_outside_project("../../etc/passwd", root)
    assert not is_outside_project("src/app.py", root)
    assert not is_outside_project("/home/user/project/src/app.py", root)


def test_no_project_root_means_no_boundary_finding() -> None:
    assert "fs.outside_project" not in _ids("/etc/passwd", root=None)
