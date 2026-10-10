"""Load and validate policy files from YAML.

A load failure (file missing, invalid YAML, schema violation) raises
``PolicyLoadError``. Callers (the engine) treat that as fail-closed: if we cannot
trust the policy set, we must not fall back to permissive behaviour.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from .schema import PolicyDocument


class PolicyLoadError(Exception):
    """Raised when a policy file cannot be read or validated."""


def load_policy_document(path: str | Path) -> PolicyDocument:
    p = Path(path)
    if not p.exists():
        raise PolicyLoadError(f"policy file not found: {p}")
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - unusual IO failure
        raise PolicyLoadError(f"cannot read policy file {p}: {exc}") from exc

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PolicyLoadError(f"invalid YAML in {p}: {exc}") from exc

    if data is None:
        raise PolicyLoadError(f"policy file is empty: {p}")
    if not isinstance(data, dict):
        raise PolicyLoadError(f"policy file must be a mapping, got {type(data).__name__}")

    try:
        doc = PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyLoadError(f"policy schema validation failed for {p}:\n{exc}") from exc

    _check_duplicate_ids(doc)
    return doc


def load_policy_document_from_string(raw: str) -> PolicyDocument:
    """Validate policy YAML held in a string (used by tests and the API validator)."""
    data = yaml.safe_load(raw)
    if not isinstance(data, dict):
        raise PolicyLoadError("policy document must be a mapping")
    try:
        doc = PolicyDocument.model_validate(data)
    except ValidationError as exc:
        raise PolicyLoadError(f"policy schema validation failed:\n{exc}") from exc
    _check_duplicate_ids(doc)
    return doc


def _check_duplicate_ids(doc: PolicyDocument) -> None:
    seen: set[str] = set()
    for policy in doc.policies:
        if policy.id in seen:
            raise PolicyLoadError(f"duplicate policy id: {policy.id}")
        seen.add(policy.id)
