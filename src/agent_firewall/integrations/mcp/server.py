"""Model Context Protocol (MCP) gateway for the Agent Firewall.

Exposes the vendor-neutral engine as an MCP server so that *any* MCP client or
orchestrator can consult the firewall before it runs a tool. This mirrors the
HTTP ``POST /v1/evaluate`` endpoint and the Claude Code ``PreToolUse`` hook, but
over the MCP transport.

It is a **consultative gate**: the server evaluates a described tool request and
returns a decision (``allow`` / ``ask`` / ``block``) with full attribution. It
never executes the tool it is judging -- the caller is responsible for honoring
the decision.

The MCP SDK (``mcp``) is an *optional* dependency (the ``[mcp]`` extra). The pure
adjudication function :func:`evaluate_tool_request` does not import it, so it can
be unit-tested and reused without the SDK installed; only :func:`build_server`
imports ``mcp`` lazily.
"""

from __future__ import annotations

import contextlib
from typing import TYPE_CHECKING, Any, Literal

from ...audit import AuditWriter
from ...config import CoreConfig
from ...engine import SecurityEngine
from ...models import TrustLevel
from ...normalize import normalize
from ...policies import load_policy_document

if TYPE_CHECKING:  # pragma: no cover - typing only
    from mcp.server.mcpserver import MCPServer

TOOL_NAME = "evaluate_tool_request"

_TOOL_DESCRIPTION = (
    "Evaluate a described agent tool request against the Agent Firewall policy "
    "and return a decision (allow / ask / block) with a risk score, matched "
    "policies/rules, findings, and an explanation. This does NOT execute the "
    "tool; the caller must honor the returned decision."
)


def evaluate_tool_request(
    tool_name: str,
    tool_input: dict[str, Any] | None = None,
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
    content_trust: str = "unknown",
    config: CoreConfig | None = None,
) -> dict[str, Any]:
    """Adjudicate one tool request and return the serialized ``SecurityDecision``.

    Pure function (no MCP import): normalize -> engine.evaluate -> best-effort
    audit -> ``decision.model_dump(mode="json")``. An unrecognized
    ``content_trust`` string falls back to :attr:`TrustLevel.UNKNOWN` rather than
    raising, so a careless caller cannot make the gate fail open on a typo.
    """
    cfg = config or CoreConfig.from_env()
    doc = load_policy_document(cfg.policy_file)
    engine = SecurityEngine(doc)

    try:
        trust = TrustLevel(content_trust)
    except ValueError:
        trust = TrustLevel.UNKNOWN

    req = normalize(
        tool_name,
        dict(tool_input or {}),
        session_id=session_id,
        agent_id=agent_id,
        project_root=str(cfg.project_root) if cfg.project_root else None,
        environment=cfg.environment,
        content_trust=trust,
    )
    decision = engine.evaluate(req)

    # Best-effort audit; a failure here must never change the security decision.
    with contextlib.suppress(Exception):
        AuditWriter(cfg.audit_log).record(req, decision)

    return decision.model_dump(mode="json")


def build_server(*, version: str = "0.1.0") -> MCPServer[Any]:
    """Construct the MCP server exposing the firewall's ``evaluate`` tool.

    Imports the ``mcp`` SDK lazily so the rest of the package works without the
    ``[mcp]`` extra installed.
    """
    try:
        from mcp.server.mcpserver import MCPServer
    except ModuleNotFoundError as exc:  # pragma: no cover - exercised via message
        raise ModuleNotFoundError(
            "The MCP gateway requires the 'mcp' package. Install it with: "
            'pip install "agent-firewall[mcp]"'
        ) from exc

    server: MCPServer[Any] = MCPServer(
        "agent-firewall",
        instructions=(
            "A runtime security gate for AI-agent tool calls. Call "
            f"'{TOOL_NAME}' before executing any tool to get an allow/ask/block "
            "decision, and honor it."
        ),
        version=version,
    )

    @server.tool(name=TOOL_NAME, description=_TOOL_DESCRIPTION)
    def _evaluate(
        tool_name: str,
        tool_input: dict[str, Any] | None = None,
        agent_id: str | None = None,
        session_id: str | None = None,
        content_trust: str = "unknown",
    ) -> dict[str, Any]:
        return evaluate_tool_request(
            tool_name,
            tool_input,
            agent_id=agent_id,
            session_id=session_id,
            content_trust=content_trust,
        )

    return server


def run(transport: Literal["stdio", "sse", "streamable-http"] = "stdio") -> None:
    """Build and run the MCP server (defaults to the stdio transport)."""
    build_server().run(transport=transport)
