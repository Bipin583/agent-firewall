# Audit Log

Every decision (from the hook or the API) is recorded as one line in an
append-only JSONL file, chained with SHA-256 so edits, reorders, and truncations
are **detectable**. Default location: `.agent_firewall/audit.jsonl`
(`AGENT_FIREWALL_AUDIT_LOG`).

Code: `src/agent_firewall/audit/` — `schemas.py` (event + hashing),
`writer.py` (append + lock), `verifier.py` (chain check + reader).

## Event shape

Each event is a flat JSON object with a fixed field set:

```
event_id, timestamp, request_id, tool_name, decision, risk_score, risk_level,
agent_id, session_id, redacted_summary, request_hash, matched_policies,
matched_rules, explanation, prev_hash, event_hash
```

Notable fields:

- `redacted_summary` — `tool_name` + a **scrubbed** resource (secrets masked via
  `detection.secrets.scrub`). Raw `tool_input` is **never** written verbatim.
- `request_hash` — SHA-256 over the canonical `{tool_name, tool_args}`, so you
  can prove *which* request a line corresponds to without storing its contents.
- `prev_hash` / `event_hash` — the chain (below).

## The hash chain

Canonical form is `json.dumps(obj, sort_keys=True, separators=(",", ":"),
ensure_ascii=False)` so any two parties hash identical bytes for the same logical
event.

- `event_hash = sha256(canonical(event_without_event_hash) + prev_hash)`.
- The first event links to `GENESIS_HASH` (64 zeros).
- Each subsequent `prev_hash` must equal the previous `event_hash`.

### Verifying

```bash
agent-firewall audit verify           # exit 0 = OK, 1 = integrity error(s)
agent-firewall audit show --limit 20
```

`verify_chain` checks, per line: valid JSON, all required fields present,
`prev_hash` linkage/ordering, and that the recomputed `event_hash` matches the
stored one (so a modified field is caught and named). An empty/absent log
verifies as OK with zero events. The same check is exposed by the API at
`GET /v1/audit/verify`.

## Concurrency

Appends are guarded by a portable lock file (`<log>.lock`, created with
`O_CREAT | O_EXCL` and a short retry/timeout). This serializes concurrent **hook
processes** on one machine so two appends never interleave or race on the
previous-hash read. The writer also refuses to append if the log's tail line is
corrupt, rather than chaining onto garbage.

## Limitations

The log is **tamper-evident, not tamper-proof** — see
[`limitations.md`](limitations.md#audit-log-audit):

- An attacker with full write access can recompute the entire chain from any
  tampered point. Detecting *that* needs an external anchor — periodically
  publishing the head hash (`VerifyResult.head_hash`) somewhere out of the
  attacker's reach. That anchoring is intentionally **future work**, not
  implemented here.
- The lock is advisory and single-machine (not a distributed lock).
- A failed audit write never changes or blocks the security decision, so under
  disk pressure you may enforce a decision without a corresponding log line.
