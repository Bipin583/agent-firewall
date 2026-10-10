"""Verify the integrity of an audit JSONL chain.

Checks, in order, for every event:
  * the line is valid JSON with the expected fields
  * ``prev_hash`` equals the previous event's ``event_hash`` (linkage/ordering)
  * the recomputed ``event_hash`` matches the stored one (no field was altered)

Returns a structured result the CLI and API can present. The first event must
link to the genesis hash.
"""

from __future__ import annotations

import contextlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .schemas import GENESIS_HASH, compute_event_hash

_REQUIRED_FIELDS = {
    "event_id", "timestamp", "request_id", "tool_name", "decision", "risk_score",
    "risk_level", "redacted_summary", "request_hash", "matched_policies",
    "matched_rules", "explanation", "prev_hash", "event_hash",
}


@dataclass
class VerifyResult:
    ok: bool
    total: int
    errors: list[str] = field(default_factory=list)
    head_hash: str = GENESIS_HASH

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "total_events": self.total,
            "errors": self.errors,
            "head_hash": self.head_hash,
        }


def verify_chain(path: str | Path) -> VerifyResult:
    p = Path(path)
    if not p.exists():
        return VerifyResult(ok=True, total=0, errors=[], head_hash=GENESIS_HASH)

    prev = GENESIS_HASH
    total = 0
    errors: list[str] = []

    with p.open("r", encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line:
                continue
            total += 1
            try:
                event = json.loads(line)
            except ValueError as exc:
                errors.append(f"line {lineno}: invalid JSON ({exc})")
                continue

            missing = _REQUIRED_FIELDS - event.keys()
            if missing:
                errors.append(f"line {lineno}: missing fields {sorted(missing)}")
                continue

            if event["prev_hash"] != prev:
                errors.append(
                    f"line {lineno}: broken linkage (prev_hash={event['prev_hash'][:12]}... "
                    f"expected {prev[:12]}...)"
                )

            body = {k: v for k, v in event.items() if k != "event_hash"}
            recomputed = compute_event_hash(body, event["prev_hash"])
            if recomputed != event["event_hash"]:
                errors.append(
                    f"line {lineno}: hash mismatch "
                    f"(event {event.get('event_id', '?')} was modified)"
                )

            prev = event["event_hash"]

    return VerifyResult(ok=not errors, total=total, errors=errors, head_hash=prev)


def read_events(path: str | Path, limit: int | None = None) -> list[dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return []
    events: list[dict[str, Any]] = []
    with p.open("r", encoding="utf-8") as fh:
        for raw in fh:
            line = raw.strip()
            if line:
                with contextlib.suppress(ValueError):
                    events.append(json.loads(line))
    if limit is not None:
        return events[-limit:]
    return events
