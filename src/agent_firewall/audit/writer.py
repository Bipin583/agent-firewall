"""Append-only audit writer with a SHA-256 hash chain.

Writes JSONL (one event per line) to a configured path. The hook calls this with
no database and no network. Concurrency: appends are guarded by a portable
lock-file (atomic O_EXCL create with retry). This makes concurrent *processes*
(multiple hook invocations) serialize their appends on the same machine. It does
NOT make the store safe against an attacker with direct file access -- see
docs/audit.md.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..detection.secrets import scrub
from ..models import NormalizedRequest, SecurityDecision
from .schemas import GENESIS_HASH, build_event, canonical_json


class AuditWriteError(Exception):
    pass


@contextlib.contextmanager
def _file_lock(target: Path, timeout: float = 5.0) -> Iterator[None]:
    lock_path = target.with_suffix(target.suffix + ".lock")
    deadline = time.monotonic() + timeout
    fd = None
    while True:
        try:
            fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError:
            if time.monotonic() > deadline:
                raise AuditWriteError(f"timed out acquiring audit lock {lock_path}") from None
            time.sleep(0.02)
    try:
        yield
    finally:
        if fd is not None:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(str(lock_path))


def _last_hash(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS_HASH
    last_line = ""
    with path.open("rb") as fh:
        for raw in fh:
            stripped = raw.strip()
            if stripped:
                last_line = stripped.decode("utf-8")
    if not last_line:
        return GENESIS_HASH
    try:
        return str(json.loads(last_line)["event_hash"])
    except (ValueError, KeyError):
        raise AuditWriteError(f"audit log {path} tail is corrupt; refusing to append") from None


def _request_summary(req: NormalizedRequest) -> str:
    bits = [req.tool_name]
    if req.resource:
        bits.append(scrub(req.resource)[:200])
    return " ".join(bits)[:300]


def _request_hash(req: NormalizedRequest) -> str:
    body = canonical_json({"tool_name": req.tool_name, "tool_args": req.tool_args})
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


class AuditWriter:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def record(self, req: NormalizedRequest, decision: SecurityDecision) -> dict[str, Any]:
        """Append one tamper-evident event and return it."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with _file_lock(self.path):
            prev = _last_hash(self.path)
            event = build_event(
                event_id=decision.decision_id,
                timestamp=decision.timestamp.isoformat(),
                request_id=req.request_id,
                tool_name=req.tool_name,
                decision=decision.decision.value,
                risk_score=decision.risk_score,
                risk_level=decision.risk_level.value,
                agent_id=req.agent_id,
                session_id=req.session_id,
                redacted_summary=_request_summary(req),
                request_hash=_request_hash(req),
                matched_policies=decision.matched_policies,
                matched_rules=decision.matched_rules,
                explanation=decision.explanation,
                prev_hash=prev,
            )
            line = canonical_json(event)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        return event
