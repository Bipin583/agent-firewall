"""Deterministic 0-100 risk scorer with per-factor explanations."""

from __future__ import annotations

from ..models import RiskFactor, RiskLevel, SecurityFinding
from .factors import (
    CATEGORY_BONUS,
    CONTEXT_WEIGHTS,
    RISK_BANDS,
    SEVERITY_WEIGHTS,
)


def level_for_score(score: int) -> RiskLevel:
    for threshold, name in RISK_BANDS:
        if score >= threshold:
            return RiskLevel(name)
    return RiskLevel.NONE


def score_request(
    findings: list[SecurityFinding],
    *,
    context_flags: dict[str, bool] | None = None,
) -> tuple[int, RiskLevel, list[RiskFactor]]:
    """Compute an additive risk score.

    Returns (score 0-100, level, ordered list of contributing factors). Each
    factor records how much it added, so the decision is fully explainable.
    """
    context_flags = context_flags or {}
    factors: list[RiskFactor] = []
    total = 0

    for finding in findings:
        base = SEVERITY_WEIGHTS.get(finding.severity, 0)
        bonus = CATEGORY_BONUS.get(finding.category, 0)
        # Scale by confidence so low-confidence/inferred findings contribute less.
        contribution = round((base + bonus) * finding.confidence)
        if contribution <= 0:
            continue
        total += contribution
        factors.append(
            RiskFactor(
                name=finding.rule_id,
                contribution=contribution,
                detail=finding.message,
            )
        )

    for flag, present in context_flags.items():
        if present and flag in CONTEXT_WEIGHTS:
            contribution = CONTEXT_WEIGHTS[flag]
            total += contribution
            factors.append(
                RiskFactor(name=flag, contribution=contribution, detail=f"context: {flag}")
            )

    score = max(0, min(100, total))
    factors.sort(key=lambda f: f.contribution, reverse=True)
    return score, level_for_score(score), factors
