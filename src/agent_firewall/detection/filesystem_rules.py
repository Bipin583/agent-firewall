"""Path-aware inspection for filesystem tools (Read/Write/Edit, and Bash targets).

What this provides:
  * normalisation of relative/absolute paths
  * detection of path-traversal (``..``) segments
  * matching against sensitive-file patterns (.env, *.pem, credentials, keys)
  * a project-boundary check (is the target inside the configured project root?)

What this does NOT provide (documented in docs/limitations.md): protection
against symlink races or TOCTOU attacks. We perform a *lexical* analysis plus an
optional real-path check; we do not freeze the filesystem. A lexical check alone
does not defeat a symlink that points outside the project.
"""

from __future__ import annotations

import os
from fnmatch import fnmatch
from pathlib import PurePosixPath

from ..models import SecurityFinding, Severity

SENSITIVE_PATTERNS: list[str] = [
    "**/.env",
    "**/.env.*",
    ".env",
    ".env.*",
    "**/credentials*",
    "**/.aws/*",
    "**/.ssh/*",
    "**/id_rsa*",
    "**/id_ed25519*",
    "**/*.pem",
    "**/*.key",
    "**/*.pfx",
    "**/*.p12",
    "**/.netrc",
    "**/.git-credentials",
    "**/secrets*.yaml",
    "**/secrets*.yml",
    "**/service-account*.json",
]


def _normalise(path: str) -> str:
    return path.replace("\\", "/")


def has_traversal(path: str) -> bool:
    """True if the path contains an upward ``..`` segment."""
    parts = PurePosixPath(_normalise(path)).parts
    return ".." in parts


def matches_sensitive(path: str) -> str | None:
    """Return the first sensitive pattern the path matches, else None."""
    norm = _normalise(path)
    base = norm.rsplit("/", 1)[-1]
    for pat in SENSITIVE_PATTERNS:
        if fnmatch(norm, pat) or fnmatch(base, pat):
            return pat
    return None


def is_outside_project(path: str, project_root: str | None) -> bool:
    """Lexically resolve ``path`` and check whether it escapes ``project_root``.

    Uses ``os.path.normpath`` (not ``Path.resolve``) so we don't touch the disk
    and don't follow symlinks here -- the symlink limitation is intentional and
    documented. Returns False when no project root is configured.
    """
    if not project_root:
        return False
    root = os.path.normpath(project_root)
    candidate = path
    if not os.path.isabs(candidate):
        candidate = os.path.join(root, candidate)
    resolved = os.path.normpath(candidate)
    try:
        common = os.path.commonpath([root, resolved])
    except ValueError:
        # Different drives on Windows -> definitely outside.
        return True
    return common != root


def inspect_path(path: str, *, action: str, project_root: str | None) -> list[SecurityFinding]:
    """Produce findings for a filesystem target.

    ``action`` is "read" or "write"; writes to sensitive files are more severe.
    """
    findings: list[SecurityFinding] = []
    if not path:
        return findings

    if has_traversal(path):
        findings.append(
            SecurityFinding(
                rule_id="fs.path_traversal",
                category="filesystem",
                severity=Severity.HIGH,
                message="Path contains an upward traversal ('..') segment",
                evidence=_normalise(path)[:120],
            )
        )

    sensitive = matches_sensitive(path)
    if sensitive:
        sev = Severity.CRITICAL if action == "write" else Severity.HIGH
        findings.append(
            SecurityFinding(
                rule_id="fs.sensitive_file",
                category="filesystem",
                severity=sev,
                message=f"{action.capitalize()} targets a sensitive file (pattern '{sensitive}')",
                evidence=_normalise(path)[:120],
            )
        )

    if is_outside_project(path, project_root):
        findings.append(
            SecurityFinding(
                rule_id="fs.outside_project",
                category="filesystem",
                severity=Severity.MEDIUM,
                message="Path resolves outside the configured project boundary (lexical check)",
                evidence=_normalise(path)[:120],
                inferred=True,
            )
        )

    return findings
