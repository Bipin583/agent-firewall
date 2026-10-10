# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **MCP gateway** (`[mcp]` extra): expose the engine as a Model Context Protocol
  server so any MCP client can consult the firewall before running a tool.
  Registers an `evaluate_tool_request` tool and ships an `agent-firewall mcp`
  CLI subcommand plus a `python -m agent_firewall.integrations.mcp` entry point.
  Documented in `docs/mcp-gateway.md`.

## [0.1.0] - 2026-10-10

First release.

### Added
- Core evaluation engine with a fixed, security-critical pipeline:
  authorization (fail-closed) → deterministic detectors → additive attributed
  risk score → declarative YAML policy evaluation → combine with precedence
  `deny > approval > allow`.
- Detectors: shell-command shapes, filesystem path analysis, secret/DLP
  scanning, and prompt-injection indicators.
- Deterministic additive risk scorer (0–100) with per-factor explanations and
  no learned component.
- Declarative YAML policy schema, loader, and evaluator, plus a bundled default
  policy set.
- Tamper-evident, hash-chained JSONL audit log with a verifier and concurrent
  append locking.
- Claude Code `PreToolUse` hook adapter and a thin stdin entry point
  (`hooks/pre_tool_use.py`).
- CLI: `evaluate`, `policy validate`, `audit show`, `audit verify`, `hook`.
- Optional FastAPI + SQLAlchemy HTTP service (`[api]` extra) exposing
  `POST /v1/evaluate`, `GET /v1/decisions`, `GET /v1/audit/verify`,
  `POST /v1/policy/validate`, and `GET /healthz` with bearer-token auth that
  fails closed when the token is unset.
- Documentation: threat model/limitations, policy engine, DLP, hook
  integration, benchmarking, and audit.
- Test suite (84 tests) with `ruff` and `mypy --strict` clean, and GitHub
  Actions CI on Python 3.11 and 3.12.

[0.1.0]: https://github.com/Bipin583/agent-firewall/releases/tag/v0.1.0
