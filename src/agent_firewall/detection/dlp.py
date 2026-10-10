"""Data-loss-prevention checks for *outgoing transfer* shaped requests.

The firewall can only inspect what the integration gives it. For the Claude Code
hook that is the tool arguments -- NOT network traffic and NOT tool output. So
DLP here means: when a request looks like it carries a payload to an external
destination (an MCP http client, a Bash curl/POST, a Write to an external mount),
inspect that payload for secrets and decide allow/block/ask via policy.

This module produces findings only; the engine + policy make the decision.
"""

from __future__ import annotations

from ..models import NormalizedRequest, SecurityFinding, Severity
from .secrets import scan_text

# Tool-arg keys that commonly carry an outbound payload.
_PAYLOAD_KEYS = ("body", "data", "payload", "content", "json", "text")
_DESTINATION_KEYS = ("url", "destination", "endpoint", "host")


def extract_destination(req: NormalizedRequest) -> str | None:
    for key in _DESTINATION_KEYS:
        val = req.tool_args.get(key)
        if isinstance(val, str) and val:
            return val
    return None


def _collect_payload(req: NormalizedRequest) -> str:
    chunks: list[str] = []
    for key in _PAYLOAD_KEYS:
        val = req.tool_args.get(key)
        if isinstance(val, str):
            chunks.append(val)
        elif val is not None:
            chunks.append(str(val))
    return "\n".join(chunks)


def inspect_transfer(req: NormalizedRequest) -> list[SecurityFinding]:
    """Flag secrets in an outbound payload. Only meaningful for NETWORK actions."""
    destination = extract_destination(req)
    payload = _collect_payload(req)
    if not payload:
        return []

    findings = scan_text(payload, source="outbound payload")
    secret_findings = [f for f in findings if f.category == "secret"]
    if secret_findings and destination:
        secret_findings.append(
            SecurityFinding(
                rule_id="dlp.secret_egress",
                category="dlp",
                severity=Severity.CRITICAL,
                message=f"Outbound payload to '{destination}' contains credential-shaped data",
                evidence=f"destination={destination[:60]}",
            )
        )
    return secret_findings
