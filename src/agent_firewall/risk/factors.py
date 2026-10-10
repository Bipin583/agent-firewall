"""Risk factor definitions and weights.

Scoring is deterministic and additive, capped at 100. Weights live here so the
model is documented in one place (docs/benchmarking.md references these). Changing
a weight changes behaviour reproducibly -- there is no learned/opaque component.

Authorization is deliberately NOT a risk factor that can be "scored away": the
engine blocks unauthorized/denied requests regardless of score. Risk only decides
between ALLOW and ASK within the space of otherwise-permitted requests, and raises
visibility.
"""

from __future__ import annotations

from ..models import Severity

# Base contribution by finding severity.
SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.INFO: 2,
    Severity.LOW: 8,
    Severity.MEDIUM: 20,
    Severity.HIGH: 40,
    Severity.CRITICAL: 60,
}

# Additional contribution by finding category (stacked on severity) so that, e.g.,
# a secret egress weighs more than a generic high finding.
CATEGORY_BONUS: dict[str, int] = {
    "dlp": 25,
    "secret": 15,
    "command": 10,
    "filesystem": 10,
    "prompt_injection": 5,
    "authorization": 30,
    "pii": 3,
}

# Contribution for contextual (non-finding) factors.
CONTEXT_WEIGHTS: dict[str, int] = {
    "destructive_action": 20,
    "external_transfer": 20,
    "untrusted_provenance": 10,
    "repeated_violation": 15,
}

RISK_BANDS: list[tuple[int, str]] = [
    (90, "critical"),
    (70, "high"),
    (40, "medium"),
    (15, "low"),
    (0, "none"),
]
