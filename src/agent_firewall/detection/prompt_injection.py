"""Prompt-injection *indicator* detection (a supporting signal, not the defence).

The real defence against prompt injection in Agent Firewall is enforcing tool
permissions and destination restrictions regardless of what the model decides to
do (Part 12). This module only raises the *risk* of a request when its content
looks like an injection attempt, so operators get visibility.

It is deterministic (phrase indicators). An optional classifier interface is
defined but intentionally not wired as an authority: ``ClassifierProtocol`` can
be supplied, but its output only adds a finding -- it can never grant ALLOW.
"""

from __future__ import annotations

import re
from typing import Protocol

from ..models import SecurityFinding, Severity, TrustLevel

_INDICATORS: list[tuple[str, re.Pattern[str]]] = [
    (
        "ignore_instructions",
        re.compile(r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions"),
    ),
    (
        "override_policy",
        re.compile(r"(?i)(disregard|override|bypass)\s+(the\s+)?(system|security|safety|policy)"),
    ),
    (
        "reveal_secrets",
        re.compile(
            r"(?i)(print|reveal|read|dump|show|exfiltrate)\s+(the\s+)?"
            r"(env|environment|secret|credential|api[\s_-]?key|token)"
        ),
    ),
    (
        "exfiltrate",
        re.compile(
            r"(?i)(upload|send|post|exfiltrate)\s+[^\n]{0,40}(to\s+)?"
            r"(http|https|ftp|external|attacker|server)"
        ),
    ),
    ("you_are_now", re.compile(r"(?i)you\s+are\s+now\s+(a|an|in)\b")),
    ("developer_mode", re.compile(r"(?i)(enable\s+)?(developer|dan|jailbreak)\s+mode")),
    ("new_instructions", re.compile(r"(?i)new\s+(system\s+)?instructions?\s*:")),
]


class ClassifierProtocol(Protocol):
    """Optional ML/LLM detector. Advisory only -- never an authorization authority."""

    def score(self, text: str) -> float: ...


def scan_content(
    text: str,
    *,
    trust: TrustLevel = TrustLevel.UNKNOWN,
    classifier: ClassifierProtocol | None = None,
) -> list[SecurityFinding]:
    if not text:
        return []
    findings: list[SecurityFinding] = []
    # Content from trusted config is not treated as an injection vector.
    is_untrusted = trust in {
        TrustLevel.EXTERNAL_DOCUMENT,
        TrustLevel.TOOL_OUTPUT,
        TrustLevel.UNKNOWN,
    }
    for name, pattern in _INDICATORS:
        if pattern.search(text):
            findings.append(
                SecurityFinding(
                    rule_id=f"pi.{name}",
                    category="prompt_injection",
                    severity=Severity.HIGH if is_untrusted else Severity.LOW,
                    message=f"Prompt-injection indicator '{name}' in {trust.value} content",
                    evidence=None,
                    confidence=0.5,
                    inferred=True,
                )
            )
    if classifier is not None:
        try:
            prob = classifier.score(text)
        except Exception:  # a broken classifier must never fail-open
            prob = 0.0
        if prob >= 0.5:
            findings.append(
                SecurityFinding(
                    rule_id="pi.classifier",
                    category="prompt_injection",
                    severity=Severity.MEDIUM,
                    message=f"Optional classifier flagged content (p={prob:.2f}); advisory only",
                    confidence=min(prob, 0.9),
                    inferred=True,
                )
            )
    return findings
