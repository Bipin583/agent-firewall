# Policy Engine

The policy engine answers one question deterministically: *given a request and
(optionally) a risk score, which policies match and what single decision do they
jointly imply?* It never executes anything and never calls an LLM.

Code: `src/agent_firewall/policies/` — `schema.py` (validated model),
`evaluator.py` (matching + precedence), `loader.py` (YAML → validated document).

## Document shape

```yaml
version: 1
default_effect: allow          # effect when NO policy matches
policies:
  - id: block-protected-credentials
    effect: deny               # deny | approval | allow
    enabled: true
    description: "..."
    # selectors (all optional):
    tools: [Read, Write, Edit, MultiEdit]
    agents: [agent-a]
    action_types: [read, write, execute, network, unknown]
    environments: [production]
    resource_patterns: ["**/.env", "**/*.pem"]
    destination_patterns: ["*.evil.example"]
    risk_threshold: 85         # 0..100; see "Risk gates"
```

The schema is **strict** (`extra="forbid"`): an unknown key is a loud load
error, never silently-ignored (and therefore never accidentally permissive). The
loader also rejects duplicate policy ids, empty/non-mapping files, and invalid
YAML. Any load failure raises `PolicyLoadError`, which the engine treats as
**fail-closed** — a policy set it cannot trust never degrades to "allow".

## Matching: AND across dimensions, OR within one

A policy matches a request when **every populated selector** matches. Within a
single selector, the listed values are alternatives:

- `tools`, `agents`, `action_types`, `environments` — exact membership
  (`_list_any`). An empty list means "no constraint on this dimension".
- `resource_patterns` — glob (`fnmatch`) against the request's resource (e.g. a
  file path). Matched against both the raw value and a `\` → `/` normalised copy,
  so Windows paths do not defeat posix patterns like `**/.env`.
- `destination_patterns` — glob against the request's `destination`/`url` arg,
  when present.
- `risk_threshold` on any effect additionally requires `risk_score >= threshold`.

## Risk gates (policy without tool enumeration)

A `deny` or `approval` policy with **only** a `risk_threshold` and no other
selectors is a *pure risk gate* (`Policy.is_pure_risk_gate`). It matches purely
on the score, letting a file say "block anything scoring ≥ 85" or "require
approval at ≥ 50" without listing every tool. This is how clearly destructive
commands get hard-denied: their detectors push the score into the deny band.

## Precedence: `deny > approval > allow`

`evaluate_policies` collects **all** matching policies first (no short-circuit,
so the result is order-independent and deterministic), then resolves:

1. Any matching `deny` → **BLOCK**. Deny always wins; a low score cannot override it.
2. Else any matching `approval` (selector match or threshold crossed) → **ASK**.
3. Else any matching `allow` → **ALLOW**.
4. Else fall back to `default_effect` (`deny`→BLOCK, `approval`→ASK, `allow`→ALLOW).

Authorization is **upstream** of this (in `engine.py`), not a policy — an
unauthorized or unknown-tool request is blocked before policies run, and risk is
applied by the engine so a score can only raise scrutiny, never rescue a deny.
See [`limitations.md`](limitations.md) for what the engine as a whole does and
does not guarantee.

## Validating a policy file

```bash
agent-firewall policy validate policies/default.yaml
```

Exits non-zero with the schema error on failure. The same validation is exposed
over HTTP by the optional API (`POST /v1/policy/validate`).
