# MCP gateway

The Agent Firewall can expose its engine as a
[Model Context Protocol](https://modelcontextprotocol.io) (MCP) server, so that
**any** MCP client or agent orchestrator can consult the firewall before it runs
a tool. This mirrors the HTTP `POST /v1/evaluate` endpoint and the Claude Code
`PreToolUse` hook, but over the MCP transport.

> It is a **consultative gate**, not a sandbox. The server evaluates a described
> tool request and returns a decision; it never executes the tool it is judging.
> The calling agent is responsible for honoring the decision. See
> [`limitations.md`](limitations.md).

## Install & run

```bash
pip install -e ".[mcp]"          # pulls the optional `mcp` SDK

agent-firewall mcp                # run over stdio (default)
# or:
python -m agent_firewall.integrations.mcp
```

The server reads the same environment configuration as the rest of the firewall
(`AGENT_FIREWALL_POLICY_FILE`, `AGENT_FIREWALL_AUDIT_LOG`,
`AGENT_FIREWALL_PROJECT_ROOT`, …) — see the configuration table in the
[`README`](../README.md#configuration).

## Wiring it into an MCP client

Point any MCP client at the command. For example, in a Claude Code / Claude
Desktop MCP config:

```json
{
  "mcpServers": {
    "agent-firewall": {
      "command": "agent-firewall",
      "args": ["mcp"],
      "env": { "AGENT_FIREWALL_POLICY_FILE": "/path/to/policies/default.yaml" }
    }
  }
}
```

## The `evaluate_tool_request` tool

The server registers a single tool, `evaluate_tool_request`:

| Argument | Type | Required | Meaning |
|----------|------|----------|---------|
| `tool_name` | string | yes | The tool being requested, e.g. `Bash`, `Read`, `WebFetch`. |
| `tool_input` | object | no | The tool's arguments (e.g. `{"command": "rm -rf /"}`). |
| `agent_id` | string | no | Identifier of the agent making the request. |
| `session_id` | string | no | Session identifier, for audit correlation. |
| `content_trust` | string | no | Provenance of the content: one of `trusted_config`, `user`, `external_document`, `tool_output`, `unknown` (default). An unrecognized value falls back to `unknown` — it never fails open. |

It returns the serialized `SecurityDecision`: `decision` (`allow` / `ask` /
`block`), `risk_score`, `risk_level`, `matched_policies`, `matched_rules`,
`findings`, `risk_factors`, and a human-readable `explanation`. Each evaluation
is appended to the audit log on a best-effort basis (an audit failure never
changes the decision).

## Design

The adjudication logic lives in a plain function,
`agent_firewall.integrations.mcp.evaluate_tool_request`, which does **not**
import the `mcp` SDK. Only `build_server()` imports it, lazily, so the rest of
the package (and that function's unit tests) work without the `[mcp]` extra
installed. This matches the pattern used by the Claude Code hook adapter, whose
pure core (`evaluate_payload`) is likewise testable without a live client.
