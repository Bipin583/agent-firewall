"""Tamper-evident audit log."""

from .schemas import GENESIS_HASH, build_event, canonical_json, compute_event_hash
from .verifier import VerifyResult, read_events, verify_chain
from .writer import AuditWriteError, AuditWriter

__all__ = [
    "GENESIS_HASH",
    "AuditWriteError",
    "AuditWriter",
    "VerifyResult",
    "build_event",
    "canonical_json",
    "compute_event_hash",
    "read_events",
    "verify_chain",
]
