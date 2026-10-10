"""Policy engine package: schema, loader, deterministic evaluator."""

from .evaluator import PolicyOutcome, evaluate_policies, policy_matches
from .loader import (
    PolicyLoadError,
    load_policy_document,
    load_policy_document_from_string,
)
from .schema import Effect, Policy, PolicyDocument

__all__ = [
    "Effect",
    "Policy",
    "PolicyDocument",
    "PolicyLoadError",
    "PolicyOutcome",
    "evaluate_policies",
    "load_policy_document",
    "load_policy_document_from_string",
    "policy_matches",
]
