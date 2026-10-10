# Claude Code Hook Integration

Agent Firewall plugs into Claude Code as a **`PreToolUse` hook**: Claude Code
runs it with the pending tool call on stdin *before* executing the tool, and the
hook returns an `allow` / `ask` / `deny` decision. The firewall only ever
*tightens* Claude Code's native permission flow — it never disables it.

- Entry point: `hooks/pre_tool_use.py` (tiny; puts `src/` on `sys.path` so the
  repo works without being pip-installed, then calls the adapter).
- Adapter: `src/agent_firewall/integrations/claude_code/hook.py`.
- Wiring: `.claude/settings.json`.

Protocol facts below were verified against the official Claude Code hook docs on
2026-10-09.

## settings.json

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch|Glob|Grep",
      "hooks": [{
        "type": "command",
        "command": "python",
        "args": ["${CLAUDE_PROJECT_DIR}/hooks/pre_tool_use.py"],
        "timeout": 10,
        "statusMessage": "Agent Firewall evaluating tool request"
      }]
    }]
  }
}
```

Remove the `hooks` block (or the file) to disable the firewall. The hook makes a
local, deterministic decision with **no network and no database** dependency.

## Input (stdin)

A JSON object with at least `hook_event_name`, `tool_name`, `tool_input`, plus
`session_id` and `cwd` which the adapter uses. A payload for a different
`hook_event_name` is ignored (the adapter defers). Missing/mis-typed
`tool_name`/`tool_input` is treated as an error (see error handling).

## Output (stdout)

Exactly one JSON object, nothing else (all diagnostics go to **stderr**):

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "<the decision's explanation>"
  }
}
```

### Decision mapping

| Engine decision | `permissionDecision` |
|-----------------|----------------------|
| `BLOCK` | `deny` |
| `ASK` | `ask` |
| `ALLOW` | *nothing emitted* — defer to Claude Code's native permission flow, unless `AGENT_FIREWALL_EMIT_ALLOW=1`, which emits an explicit `allow` |

Deferring on allow is deliberate: emitting `allow` would *bypass* Claude Code's
own prompts, so by default the firewall stays silent on allow and only speaks up
to `ask` or `deny`.

## Error handling (fail-safe)

Controlled by `AGENT_FIREWALL_ON_ERROR` (default `ask`). If the hook cannot parse
its input, load the policy, or evaluate the request, it responds per this
setting rather than crashing:

- `ask` (default) → surface to the human,
- `deny` → block,
- `allow` → defer to native flow (least safe; not recommended).

The hook always exits `0` and expresses the decision in JSON (it does not rely on
exit-2-to-block). If the package cannot even be imported, the thin entry point
emits a hard-coded `ask` so a broken install never silently allows.

## Auditing

After each decision the adapter best-effort appends a tamper-evident audit event
(`AGENT_FIREWALL_AUDIT_LOG`, default `.agent_firewall/audit.jsonl`). An audit
write failure is logged to stderr but **never changes the enforced decision** —
logging must not become a fail-open path. See [`audit.md`](audit.md).

## Identity caveat

The hook receives a `session_id`, not a strong agent identity, so by default
every *known* tool is authorized and unknown tools fail closed. Per-agent
allowlists are only meaningful for integrations that supply a trustworthy
`agent_id` (e.g. a gateway or the HTTP API). See
[`limitations.md`](limitations.md#authorization-authorizationpy).

## Configuration

See the env-var table in the top-level `README.md`
(`src/agent_firewall/config.py` is the source of truth). The core path reads
only policy/audit/env/on-error/project-root; the API DB/token vars are read
lazily and never pulled into the hook.
