# Secret Detection & DLP

Two cooperating modules, both deterministic and pattern-based:

- `detection/secrets.py` — find credential- and PII-shaped strings in any text,
  with always-redacted evidence.
- `detection/dlp.py` — when a request looks like it carries a payload to an
  external destination, scan that payload for secrets so policy can gate egress.

Neither prevents a leak on its own; they produce **findings**, and the engine +
policy make the `allow`/`ask`/`block` decision.

## Secret patterns

`scan_text(text, source=...)` returns at most **one finding per pattern** (so a
file full of emails does not flood the result). Current patterns:

| rule_id | what | severity |
|---------|------|----------|
| `secret.aws_access_key` | `AKIA…`/`ASIA…` key id | high |
| `secret.aws_secret_key` | `aws_secret_access_key = <40 chars>` | critical |
| `secret.github_token` | `ghp_`/`gho_`/`ghu_`/… | high |
| `secret.slack_token` | `xoxb-`/`xoxp-`/… | high |
| `secret.openai_key` | `sk-…` | high |
| `secret.anthropic_key` | `sk-ant-…` | high |
| `secret.private_key_header` | `-----BEGIN … PRIVATE KEY-----` | critical |
| `secret.password_assignment` | `password=…` / `api_key: …` | medium |
| `secret.generic_bearer` | `Bearer <token>` | medium |
| `pii.email` | email address | low |

Patterns are intentionally **conservative to limit false positives** — which
means false negatives are expected. See
[`limitations.md`](limitations.md#secret-detection--dlp-detectionsecretspy-detectiondlppy).

## Redaction (secrets never land in logs)

- `redact(value, keep=4)` masks all but a short recognisable prefix.
- `scrub(text)` replaces every known secret-shaped substring in a block of text
  with its redacted form (PII patterns are skipped to keep summaries readable).

The audit writer calls `scrub` on request summaries, and every `SecurityFinding`
built here carries pre-redacted `evidence` (e.g. `AWS access key id: AKIA****…`).
A live credential should never appear in a finding, an explanation, or the audit
log.

## DLP on outbound transfers

`inspect_transfer(req)` only does meaningful work for `NETWORK`-shaped requests.
It:

1. extracts a destination from `url`/`destination`/`endpoint`/`host`,
2. collects a payload from `body`/`data`/`payload`/`content`/`json`/`text`,
3. runs `scan_text` over the payload, keeps the `secret`-category findings, and
4. if secrets **and** a destination are both present, adds a critical
   `dlp.secret_egress` finding naming the (truncated) destination.

That `dlp` finding carries a large category bonus in the risk model
(`risk/factors.py`), so credential egress reliably scores into the deny band.

## What DLP cannot see

The firewall only inspects **tool arguments** the integration passes it. For the
Claude Code hook that is *not* real network bytes and *not* a tool's output. A
secret exfiltrated through a channel that never appears in a scanned argument
(an interpreter building the request at runtime, a field name we don't collect,
an encoded blob) is invisible to DLP. Treat this layer as raising cost and
visibility, not as a guarantee.
