"""Deterministic security detectors.

Each detector is a pure function from input text/request to a list of
``SecurityFinding``. Detectors never make the final decision and never execute
anything -- the engine aggregates findings, the risk scorer weights them, and the
policy engine decides.
"""

from .command_rules import inspect_command
from .dlp import extract_destination, inspect_transfer
from .filesystem_rules import (
    has_traversal,
    inspect_path,
    is_outside_project,
    matches_sensitive,
)
from .prompt_injection import scan_content
from .secrets import contains_secret, redact, scan_text

__all__ = [
    "contains_secret",
    "extract_destination",
    "has_traversal",
    "inspect_command",
    "inspect_path",
    "inspect_transfer",
    "is_outside_project",
    "matches_sensitive",
    "redact",
    "scan_content",
    "scan_text",
]
