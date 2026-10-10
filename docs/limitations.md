# Limitations & Threat Model

Agent Firewall is a **runtime policy gate**, not a sandbox. It evaluates a tool
request *before* an agent executes it and returns `allow` / `ask` / `block`. It
never runs the requested tool to find out whether it is safe, and it can only
reason about the information the integration hands it (for the Claude Code hook,
that is `tool_name` + `tool_input` — not live network traffic, not tool output,
not the actual bytes on disk).

Read this document as the honest boundary of what the firewall does and does not
stop. Each detector module links here from its docstring on purpose.

## Design stance (what we deliberately refuse to do)

- **Deterministic, explainable decisions.** Detection is regex/lexical and risk
  scoring is additive with per-factor attribution (`src/agent_firewall/risk/`).
  There is no learned or opaque component that can silently change behaviour.
- **Fail-closed.** Unknown tools, authorization failures, detector crashes, and
  policy-load errors never silently `allow`. They degrade to `block` or `ask`
  (the hook's `AGENT_FIREWALL_ON_ERROR` default is `ask`).
- **Risk cannot buy an allow.** A high score can only *raise* scrutiny
  (`allow` → `ask` → `block`). A low score can never rescue a request that
  authorization or a `deny` policy already rejected. Precedence is
  `deny > approval > allow`.
- **The firewall never executes anything.** It is advice-at-the-gate, enforced
  by the host (Claude Code's permission system) acting on the returned decision.

## Command inspection (`detection/command_rules.py`)

Regex + `shlex` **cannot secure an arbitrary shell.** We detect *clear,
well-known dangerous shapes* and flag *unparseable* input as uncertain so policy
(not a silent allow) decides. Known evasions we do **not** claim to catch:

- Base64/hex/other encodings decoded at runtime, payloads built from variables
  (`X=rm; $X -rf /`), or read from a file / heredoc / stdin.
- Programs run through interpreters we can't statically evaluate (`python -c`,
  `node -e`, `eval`). We *flag* these as opaque (`cmd.opaque_payload`) rather
  than decode them.
- Novel destructive commands outside the known-shape list, obscure tool flags,
  or shell features (process substitution variants, globbing) that change
  meaning after the string we see.

`rm` is handled flag-aware (fused `-rf`, reordered `-fr`, separated `-r -f`,
long `--recursive --force`, mixed-case `-Rf`), but the above encoding/indirection
evasions still apply to it. Root/home classification (`cmd.rm_rf_root`) only
fires on a bare `/`, `~`, `/*`, `$HOME`, or `%USERPROFILE%` target — a deletion
of `/etc` or `/tmp/x` is treated as generic-but-still-high `cmd.rm_rf_generic`.

## Filesystem inspection (`detection/filesystem_rules.py`)

Path analysis is **lexical**. `is_outside_project` uses `os.path.normpath`
(not `Path.resolve`) so it never touches the disk. Consequences:

- **No symlink / TOCTOU protection.** A path that lexically sits inside the
  project but is (or later becomes) a symlink pointing outside is **not** caught.
  We do not freeze the filesystem between decision and execution.
- Sensitive-file matching is pattern-based (`**/.env`, `**/*.pem`, `**/.ssh/*`,
  …). A credential file with an unusual name or extension can slip past.
- Traversal detection keys on literal `..` segments; it will not resolve an
  absolute path that reaches a sensitive location without `..`.

## Secret detection & DLP (`detection/secrets.py`, `detection/dlp.py`)

Pattern-based and **conservative to limit false positives**, which means false
negatives are expected:

- Novel/rotated token formats, secrets split across multiple fields, or any
  base64/compressed blob can evade the patterns.
- DLP only inspects *tool arguments* that look like an outbound payload
  (`body`/`data`/`content`/… toward a `url`/`destination`/…). It does **not**
  see real network bytes or a tool's output, so exfiltration through a channel
  the integration doesn't surface is invisible to it.
- Evidence is always redacted (`redact`/`scrub`), and the audit writer scrubs
  summaries — but detection ≠ prevention of a leak that never reaches a scanned
  field.

## Prompt injection (`detection/prompt_injection.py`)

This module is a **visibility signal, not the defence.** It raises risk when
content *looks like* an injection attempt (phrase indicators, optional advisory
classifier). The actual mitigation is enforcing tool permissions and destination
restrictions regardless of what the model was convinced to do. An injection
phrased outside the indicator list raises no finding; conversely benign text can
trip an indicator (findings are low-confidence/`inferred`).

## Authorization (`authorization.py`)

The Claude Code hook provides a `session_id`, **not a strong agent identity.**
By default every *known* tool is authorized and unknown tools fail closed. A
per-agent allowlist exists but is only meaningful for integrations (gateway /
MCP) that supply a trustworthy `agent_id`.

## Audit log (`audit/`)

The JSONL log is **tamper-evident, not tamper-proof.** A SHA-256 hash chain lets
`agent-firewall audit verify` detect truncation or edits, and appends serialize
via an `O_EXCL` lock file across processes on one machine. But:

- An attacker with direct write access can rewrite the whole chain (there is no
  external anchor / remote attestation).
- The lock is advisory and single-machine; it is not a distributed lock.
- A failed audit write never changes the security decision (logging must not
  become a fail-open path), so under disk pressure you may enforce without a log
  line.

## Overall scope boundary

The firewall is one layer. It assumes a cooperating host that honours its
decisions, and it only sees what that host passes at the pre-execution boundary.
It raises the cost and visibility of dangerous actions; it does not replace OS
sandboxing, least-privilege credentials, network egress controls, or review of
the agent's own configuration.
