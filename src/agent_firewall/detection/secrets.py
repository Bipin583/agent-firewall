"""Deterministic secret / credential detection.

Pattern-based. This finds *common, well-shaped* secrets. It is explicitly NOT a
guarantee: a novel token format, a base64 blob, or a secret split across fields
can evade it. Limits are documented in docs/dlp.md.

All test fixtures use synthetic values. ``redact`` is used both here and by the
audit writer so credentials never land in logs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import SecurityFinding, Severity


@dataclass(frozen=True)
class _Pattern:
    rule_id: str
    label: str
    regex: re.Pattern[str]
    severity: Severity


# Each pattern is intentionally conservative to limit false positives.
_PATTERNS: list[_Pattern] = [
    _Pattern(
        "secret.aws_access_key",
        "AWS access key id",
        re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
        Severity.HIGH,
    ),
    _Pattern(
        "secret.aws_secret_key",
        "AWS secret access key",
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
        Severity.CRITICAL,
    ),
    _Pattern(
        "secret.github_token",
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
        Severity.HIGH,
    ),
    _Pattern(
        "secret.slack_token",
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        Severity.HIGH,
    ),
    _Pattern(
        "secret.openai_key",
        "OpenAI-style API key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        Severity.HIGH,
    ),
    _Pattern(
        "secret.anthropic_key",
        "Anthropic API key",
        re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
        Severity.HIGH,
    ),
    _Pattern(
        "secret.private_key_header",
        "Private key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    _Pattern(
        "secret.password_assignment",
        "Password assignment",
        re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[=:]\s*['\"]?([^\s'\";]{6,})"),
        Severity.MEDIUM,
    ),
    _Pattern(
        "secret.generic_bearer",
        "Bearer token",
        re.compile(r"(?i)bearer\s+[A-Za-z0-9._-]{20,}"),
        Severity.MEDIUM,
    ),
    _Pattern(
        "pii.email",
        "Email address",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        Severity.LOW,
    ),
]


def redact(value: str, keep: int = 4) -> str:
    """Mask the middle of a string, keeping a short prefix for recognisability."""
    if len(value) <= keep:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep)


def scan_text(text: str, *, source: str = "input") -> list[SecurityFinding]:
    """Return a finding per distinct secret pattern that matches ``text``.

    Evidence is always redacted. We report at most one finding per pattern to
    avoid flooding (e.g. a file full of emails).
    """
    if not text:
        return []
    findings: list[SecurityFinding] = []
    for pat in _PATTERNS:
        match = pat.regex.search(text)
        if not match:
            continue
        # Prefer the captured group (the secret itself) for redaction when present.
        raw = match.group(1) if match.groups() else match.group(0)
        findings.append(
            SecurityFinding(
                rule_id=pat.rule_id,
                category="secret" if pat.rule_id.startswith("secret") else "pii",
                severity=pat.severity,
                message=f"{pat.label} detected in {source}",
                evidence=f"{pat.label}: {redact(raw)}",
            )
        )
    return findings


def contains_secret(text: str) -> bool:
    return any(f.category == "secret" for f in scan_text(text))


def scrub(text: str) -> str:
    """Replace secret-shaped substrings with a redacted form.

    Used by the audit writer so a stored request summary never contains a live
    credential. Best-effort: only known patterns are scrubbed.
    """
    if not text:
        return text
    scrubbed = text
    for pat in _PATTERNS:
        if pat.rule_id.startswith("pii"):
            continue  # emails/PII are low severity; keep summary readable

        def _repl(m: re.Match[str]) -> str:
            raw = m.group(1) if m.groups() else m.group(0)
            return m.group(0).replace(raw, redact(raw))

        scrubbed = pat.regex.sub(_repl, scrubbed)
    return scrubbed
