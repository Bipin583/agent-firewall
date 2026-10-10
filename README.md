# Agent Firewall

[![CI](https://github.com/Bipin583/agent-firewall/actions/workflows/ci.yml/badge.svg)](https://github.com/Bipin583/agent-firewall/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A runtime security and governance layer that evaluates **AI-agent tool requests
before they execute** and returns one of three decisions: `allow`, `ask`
(require human approval), or `block`.

The engine is vendor-neutral and dependency-light (just `pydantic` + `PyYAML`)
so it can run inside a Claude Code `PreToolUse` hook with **no network and no
database**. The same engine can back an MCP gateway or an HTTP service.

> It is a policy gate, not a sandbox. It never executes the tool it is judging,
> and it only reasons about what the integration hands it. Read
> [`docs/limitations.md`](docs/limitations.md) for the honest threat model
> before you rely on it.

## How it works

Every request flows through a fixed, security-critical pipeline
(`src/agent_firewall/engine.py`):

1. **Authorization (fail-closed).** Unknown tools and unauthorized agents are
   rejected before anything else. (`authorization.py`)
2. **Detection.** Deterministic detectors appropriate to the action type run:
   shell-command shapes, filesystem path analysis, secret/DLP scanning, and
   prompt-injection *indicators*. (`detection/`)
3. **Risk scoring.** Findings are turned into an additive, fully attributed
   0–100 score with per-factor explanations — no learned component. (`risk/`)
4. **Policy evaluation.** Declarative YAML policies decide `allow` / `approval`
   / `deny`, with the risk score available as a threshold. (`policies/`)
5. **Combine.** Precedence is **`deny > approval > allow`**. A high score can
   only raise scrutiny; it can never rescue a denied request, and a low score
   can never override a `deny`.

Each decision is explainable (`explanation`, `matched_policies`,
`matched_rules`, `risk_factors`) and recorded to a tamper-evident audit log.

## Install

Requires Python ≥ 3.11.

```bash
pip install -e .          # core engine + CLI
pip install -e ".[dev]"   # + pytest, ruff, mypy, hypothesis
pip install -e ".[api]"   # + optional FastAPI/SQLAlchemy service deps
pip install -e ".[mcp]"   # + optional MCP gateway deps
```

The repo also works **without** installing: `hooks/pre_tool_use.py` inserts
`src/` onto `sys.path` itself.

## Use it as a Claude Code hook

`.claude/settings.json` already wires the firewall as a `PreToolUse` hook over
the file, shell, and network tools:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Read|Write|Edit|MultiEdit|NotebookEdit|WebFetch|Glob|Grep",
      "hooks": [{
        "type": "command",
        "command": "python",
        "args": ["${CLAUDE_PROJECT_DIR}/hooks/pre_tool_use.py"],
        "timeout": 10
      }]
    }]
  }
}
```

Decision mapping to the hook protocol:

| Engine decision | `permissionDecision` |
|-----------------|----------------------|
| `BLOCK`         | `deny`               |
| `ASK`           | `ask`                |
| `ALLOW`         | *deferred* to Claude Code's native flow (nothing emitted) unless `AGENT_FIREWALL_EMIT_ALLOW=1` |

Deferring on `allow` means the firewall never *disables* native permission
controls — it only ever tightens them. Remove the `hooks` block (or the file) to
disable it entirely.

## CLI

```bash
# Evaluate a synthetic request and print the full decision as JSON
agent-firewall evaluate --tool Bash --input '{"command": "rm -rf /"}'

# Validate a policy file against the schema
agent-firewall policy validate policies/default.yaml

# Inspect / verify the audit log
agent-firewall audit show --limit 20
agent-firewall audit verify
```

(`agent-firewall hook` runs the same stdin-driven hook adapter directly.)

## Use it as an MCP gateway

The same engine can be exposed as a
[Model Context Protocol](https://modelcontextprotocol.io) server so any MCP
client can consult the firewall before running a tool:

```bash
pip install -e ".[mcp]"
agent-firewall mcp        # serve over stdio
```

It registers one tool, `evaluate_tool_request`, that returns an
`allow` / `ask` / `block` decision for a described request. It is a consultative
gate — the calling agent must honor the decision. See
[`docs/mcp-gateway.md`](docs/mcp-gateway.md).

## Policies

Policies are declarative YAML (`policies/default.yaml`). Selectors within a
policy are **ANDed**; lists within a selector are **ORed**. Effects are `allow`,
`approval`, or `deny`, with `deny` winning. The bundled set:

- `block-protected-credentials` — never read/write `.env`, keys, `.ssh`, `.aws`, …
- `block-critical-risk` — deny anything scoring ≥ 85 (how `rm -rf /`, `mkfs`,
  fork bombs, secret egress get hard-blocked — the score can't be argued away)
- `require-approval-elevated-risk` — score ≥ 50 (< 85) needs human approval
- `require-approval-network-egress` — outbound tools (`WebFetch`) need approval
- `allow-project-reads` — reading non-sensitive files is allowed

## Configuration

Read from the environment (`src/agent_firewall/config.py`):

| Variable | Default | Meaning |
|----------|---------|---------|
| `AGENT_FIREWALL_POLICY_FILE` | bundled `policies/default.yaml` | policy document |
| `AGENT_FIREWALL_AUDIT_LOG` | `.agent_firewall/audit.jsonl` | audit log path |
| `AGENT_FIREWALL_ON_ERROR` | `ask` | fail mode on error: `ask` / `deny` / `allow` |
| `AGENT_FIREWALL_PROJECT_ROOT` | cwd | project boundary for path checks |
| `AGENT_FIREWALL_ENV` | `development` | environment label |
| `AGENT_FIREWALL_EMIT_ALLOW` | unset | set `1` to emit explicit `allow` |

## Audit log

Append-only JSONL with a SHA-256 hash chain; `audit verify` detects truncation
or edits, and concurrent processes serialize appends via a lock file. Request
summaries are secret-scrubbed and raw tool input is never written verbatim. It
is **tamper-evident, not tamper-proof** — see
[`docs/limitations.md`](docs/limitations.md#audit-log-audit).

## Development

```bash
python -m pytest        # test suite (unit tests in tests/)
python scripts/smoke_test.py   # end-to-end sanity check on synthetic inputs
ruff check .            # lint
mypy                    # strict type-check
```

All test fixtures and smoke-test inputs use **synthetic** credentials and safe,
non-executed command strings.

## Project layout

```
src/agent_firewall/
  engine.py           core evaluation pipeline
  authorization.py    fail-closed identity/tool gate
  normalize.py        vendor payload -> NormalizedRequest
  models.py           typed domain models (pydantic)
  config.py           env-driven CoreConfig
  detection/          command / filesystem / secrets / dlp / prompt-injection
  risk/               deterministic additive scorer + weights
  policies/           YAML schema, loader, evaluator
  audit/              hash-chained JSONL writer + verifier
  integrations/claude_code/   PreToolUse hook adapter
  integrations/mcp/           MCP gateway server (optional [mcp] extra)
hooks/pre_tool_use.py thin stdin entry point for Claude Code
policies/default.yaml bundled policy set
docs/limitations.md   threat model & known gaps
```

## License

MIT.
