"""Typed domain models for Agent Firewall.

These models are the contract between every subsystem: normalization produces a
``NormalizedRequest``; the engine consumes it and returns a ``SecurityDecision``.
Only at the integration boundary (the Claude Code hook) are these translated into
the vendor-specific hook protocol. Keeping the internal model vendor-neutral is
what lets the same engine protect MCP tools, a gateway, etc.

Everything here is pure data + validation (Pydantic v2). No I/O, no policy logic.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Decision(StrEnum):
    """The three outcomes the firewall can produce."""

    ALLOW = "allow"
    BLOCK = "block"
    ASK = "ask"


class ActionType(StrEnum):
    """Coarse classification of what a tool call *does*, independent of tool name."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    UNKNOWN = "unknown"


class RiskLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TrustLevel(StrEnum):
    """Where request content came from. Drives prompt-injection handling."""

    TRUSTED_CONFIG = "trusted_config"
    USER = "user"
    EXTERNAL_DOCUMENT = "external_document"
    TOOL_OUTPUT = "tool_output"
    UNKNOWN = "unknown"


class NormalizedRequest(BaseModel):
    """A tool request after it has been parsed into a vendor-neutral shape.

    ``raw_tool_input`` is retained for evaluation but is NEVER written verbatim to
    the audit log; the audit writer stores only a redacted summary.
    """

    model_config = ConfigDict(frozen=True)

    request_id: str = Field(default_factory=lambda: _new_id("req"))
    agent_id: str | None = None
    session_id: str | None = None
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    resource: str | None = None
    action_type: ActionType = ActionType.UNKNOWN
    environment: str = "development"
    cwd: str | None = None
    project_root: str | None = None
    content_trust: TrustLevel = TrustLevel.UNKNOWN
    provenance_refs: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=_utcnow)
    raw_tool_input: dict[str, Any] = Field(default_factory=dict)


class SecurityFinding(BaseModel):
    """A single thing a detector noticed. Evidence is pre-redacted by the detector."""

    model_config = ConfigDict(frozen=True)

    rule_id: str
    category: str
    severity: Severity
    message: str
    evidence: str | None = None
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    inferred: bool = False


class RiskFactor(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    contribution: int
    detail: str = ""


class SecurityDecision(BaseModel):
    """The engine's verdict. This is what the hook adapter translates to the wire."""

    model_config = ConfigDict(frozen=True)

    decision_id: str = Field(default_factory=lambda: _new_id("dec"))
    request_id: str
    decision: Decision
    risk_score: int = Field(ge=0, le=100)
    risk_level: RiskLevel
    matched_policies: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    findings: list[SecurityFinding] = Field(default_factory=list)
    risk_factors: list[RiskFactor] = Field(default_factory=list)
    explanation: str = ""
    timestamp: datetime = Field(default_factory=_utcnow)
