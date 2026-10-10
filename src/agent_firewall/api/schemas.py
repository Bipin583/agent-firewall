"""Request/response models for the HTTP API boundary.

These are separate from the internal domain models on purpose: the wire contract
can evolve independently, and we never accept a raw ``NormalizedRequest`` from an
untrusted client (the server builds that itself via ``normalize``).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class EvaluateRequest(BaseModel):
    tool_name: str = Field(..., min_length=1)
    tool_input: dict[str, Any] = Field(default_factory=dict)
    agent_id: str | None = None
    session_id: str | None = None
    environment: str | None = None
    # One of the TrustLevel values; invalid/absent -> treated as "unknown".
    content_trust: str | None = None


class PolicyValidateRequest(BaseModel):
    document: str = Field(..., description="Policy document as YAML text.")


class PolicyValidateResponse(BaseModel):
    ok: bool
    policy_count: int | None = None
    default_effect: str | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    status: str
    policy_file: str
    policies_loaded: int
    audit_log: str
    auth_configured: bool
