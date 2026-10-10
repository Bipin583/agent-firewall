"""Audit event schema and canonical hashing primitives.

Each audit event is a flat JSON object. Integrity comes from a SHA-256 hash
chain: every event stores ``prev_hash`` (the previous event's ``event_hash``) and
its own ``event_hash`` computed over the canonical serialization of all fields
*except* ``event_hash`` itself.

Canonical form = ``json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)``. Two parties computing the hash of the same logical event
get the same bytes.

LIMITATION (docs/audit.md): a hash chain detects edits/reorders/truncations of a
stored chain, but an attacker with full write access to the store can recompute
the entire chain from any tampered point. Detecting that requires an external
anchor (e.g. periodically publishing the head hash elsewhere), which is noted as
future work.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

GENESIS_HASH = "0" * 64


def canonical_json(obj: dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_event_hash(event_without_hash: dict[str, Any], prev_hash: str) -> str:
    """Hash the canonical event body together with the previous hash."""
    payload = canonical_json(event_without_hash) + prev_hash
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def build_event(
    *,
    event_id: str,
    timestamp: str,
    request_id: str,
    tool_name: str,
    decision: str,
    risk_score: int,
    risk_level: str,
    agent_id: str | None,
    session_id: str | None,
    redacted_summary: str,
    request_hash: str,
    matched_policies: list[str],
    matched_rules: list[str],
    explanation: str,
    prev_hash: str,
) -> dict[str, Any]:
    """Assemble an event dict and attach its ``event_hash``.

    The field set is fixed and ordering-independent (we hash canonically).
    """
    body: dict[str, Any] = {
        "event_id": event_id,
        "timestamp": timestamp,
        "request_id": request_id,
        "tool_name": tool_name,
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "agent_id": agent_id,
        "session_id": session_id,
        "redacted_summary": redacted_summary,
        "request_hash": request_hash,
        "matched_policies": matched_policies,
        "matched_rules": matched_rules,
        "explanation": explanation,
        "prev_hash": prev_hash,
    }
    body["event_hash"] = compute_event_hash(body, prev_hash)
    return body
