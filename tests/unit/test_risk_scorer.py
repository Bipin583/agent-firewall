from __future__ import annotations

from agent_firewall.models import RiskLevel, SecurityFinding, Severity
from agent_firewall.risk import score_request
from agent_firewall.risk.scorer import level_for_score


def _finding(
    severity: Severity, category: str = "command", confidence: float = 1.0
) -> SecurityFinding:
    return SecurityFinding(
        rule_id=f"test.{category}",
        category=category,
        severity=severity,
        message="x",
        confidence=confidence,
    )


def test_empty_findings_score_zero() -> None:
    score, level, factors = score_request([])
    assert score == 0
    assert level is RiskLevel.NONE
    assert factors == []


def test_severity_and_category_stack() -> None:
    # critical severity (60) + command category bonus (10) = 70.
    score, level, _ = score_request([_finding(Severity.CRITICAL, "command")])
    assert score == 70
    assert level is RiskLevel.HIGH


def test_confidence_scales_contribution() -> None:
    full, _, _ = score_request([_finding(Severity.HIGH, "command", confidence=1.0)])
    half, _, _ = score_request([_finding(Severity.HIGH, "command", confidence=0.5)])
    assert half < full
    assert half == round(full * 0.5)


def test_context_flags_add_weight() -> None:
    base, _, _ = score_request([_finding(Severity.LOW, "command")])
    with_ctx, _, factors = score_request(
        [_finding(Severity.LOW, "command")],
        context_flags={"destructive_action": True, "external_transfer": False},
    )
    assert with_ctx == base + 20
    assert any(f.name == "destructive_action" for f in factors)


def test_score_is_clamped_to_100() -> None:
    many = [_finding(Severity.CRITICAL, "dlp") for _ in range(5)]
    score, level, _ = score_request(many)
    assert score == 100
    assert level is RiskLevel.CRITICAL


def test_factors_sorted_by_contribution_desc() -> None:
    _, _, factors = score_request([_finding(Severity.LOW), _finding(Severity.CRITICAL)])
    contributions = [f.contribution for f in factors]
    assert contributions == sorted(contributions, reverse=True)


def test_level_bands() -> None:
    assert level_for_score(95) is RiskLevel.CRITICAL
    assert level_for_score(70) is RiskLevel.HIGH
    assert level_for_score(40) is RiskLevel.MEDIUM
    assert level_for_score(15) is RiskLevel.LOW
    assert level_for_score(0) is RiskLevel.NONE
