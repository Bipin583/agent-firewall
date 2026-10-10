"""Identity and authorization layer.

Separate from both policy and risk. Answers: *is this agent even allowed to use
this tool at all?* Authorization failures and unknown tools are fail-closed:
Part 7 rule #2 ("unknown tools must not be automatically trusted") and #3
("explicit authorization restrictions take precedence over general allow rules").

The Claude Code hook provides only a session id, not a strong agent identity, so
by default every known tool is authorized. Operators can supply an
``AuthorizationPolicy`` (e.g. for a gateway or MCP integration) that restricts
specific agents to specific tools.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import NormalizedRequest, SecurityFinding, Severity

# Tools whose schemas we understand and can evaluate (Part 8 coverage).
KNOWN_TOOLS: frozenset[str] = frozenset(
    {"Bash", "Read", "Write", "Edit", "MultiEdit", "Glob", "Grep", "NotebookEdit", "WebFetch"}
)


def is_known_tool(tool_name: str) -> bool:
    return tool_name in KNOWN_TOOLS or tool_name.startswith("mcp__")


@dataclass(frozen=True)
class AuthorizationResult:
    authorized: bool
    findings: list[SecurityFinding] = field(default_factory=list)
    reason: str = ""


@dataclass(frozen=True)
class AuthorizationPolicy:
    """Optional per-agent tool allowlist. Empty allowlist for an agent means the
    agent may use any *known* tool. ``unknown_tool_authorized`` controls whether an
    unrecognised tool is permitted to proceed to policy evaluation at all."""

    agent_tool_allowlist: dict[str, set[str]] = field(default_factory=dict)
    unknown_tool_authorized: bool = False

    def check(self, req: NormalizedRequest) -> AuthorizationResult:
        findings: list[SecurityFinding] = []

        if not is_known_tool(req.tool_name):
            findings.append(
                SecurityFinding(
                    rule_id="authorization.unknown_tool",
                    category="authorization",
                    severity=Severity.MEDIUM,
                    message=f"Tool '{req.tool_name}' is not recognised; not auto-trusted",
                )
            )
            if not self.unknown_tool_authorized:
                return AuthorizationResult(False, findings, "unknown tool is not authorized")

        if req.agent_id and req.agent_id in self.agent_tool_allowlist:
            allowed = self.agent_tool_allowlist[req.agent_id]
            if allowed and req.tool_name not in allowed:
                findings.append(
                    SecurityFinding(
                        rule_id="authorization.tool_not_allowed",
                        category="authorization",
                        severity=Severity.HIGH,
                        message=(
                            f"Agent '{req.agent_id}' is not authorized "
                            f"for tool '{req.tool_name}'"
                        ),
                    )
                )
                return AuthorizationResult(False, findings, "agent not authorized for tool")

        return AuthorizationResult(True, findings, "authorized")


DEFAULT_AUTHORIZATION = AuthorizationPolicy()
