"""Agent Firewall: a runtime security layer for AI-agent tool requests.

The security engine is vendor-neutral and dependency-light so it can run inside a
Claude Code hook with no database or network. Integrations translate vendor
payloads to/from the models in :mod:`agent_firewall.models`.
"""

from .authorization import AuthorizationPolicy
from .config import CoreConfig
from .engine import SecurityEngine, evaluate_request
from .models import (
    ActionType,
    Decision,
    NormalizedRequest,
    RiskLevel,
    SecurityDecision,
    SecurityFinding,
    Severity,
    TrustLevel,
)
from .normalize import normalize

__version__ = "0.1.0"

__all__ = [
    "ActionType",
    "AuthorizationPolicy",
    "CoreConfig",
    "Decision",
    "NormalizedRequest",
    "RiskLevel",
    "SecurityDecision",
    "SecurityEngine",
    "SecurityFinding",
    "Severity",
    "TrustLevel",
    "__version__",
    "evaluate_request",
    "normalize",
]
