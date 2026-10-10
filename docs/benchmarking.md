# Risk Model & Benchmarking

Risk scoring is **deterministic, additive, and fully attributed** — there is no
learned or opaque component. Changing a weight changes behaviour reproducibly.
All weights live in one place: `src/agent_firewall/risk/factors.py`. The scorer
is `risk/scorer.py`.

Risk never buys an `allow`: a high score only escalates scrutiny
(`allow`→`ask`→`block` via policy thresholds), and authorization/deny decisions
are made independently so a score can never rescue a rejected request.

## How a score is computed

`score_request(findings, context_flags=...)` returns `(score 0..100, level,
factors)`:

1. **Per-finding contribution** = `(SEVERITY_WEIGHTS[severity] +
   CATEGORY_BONUS[category]) * confidence`, rounded. Low-confidence / inferred
   findings therefore contribute less. Non-positive contributions are dropped.
2. **Context contributions** add fixed amounts for `CONTEXT_WEIGHTS` flags the
   engine sets (`destructive_action`, `external_transfer`,
   `untrusted_provenance`, `repeated_violation`).
3. The total is clamped to `[0, 100]`, and every contributor is returned as a
   `RiskFactor(name, contribution, detail)` sorted by contribution — this is the
   explanation surfaced in the decision.

### Current weights

| severity | weight |  | category | bonus |  | context flag | weight |
|----------|-------:|--|----------|------:|--|--------------|------:|
| info | 2 |  | dlp | 25 |  | destructive_action | 20 |
| low | 8 |  | authorization | 30 |  | external_transfer | 20 |
| medium | 20 |  | secret | 15 |  | untrusted_provenance | 10 |
| high | 40 |  | command | 10 |  | repeated_violation | 15 |
| critical | 60 |  | filesystem | 10 |  | | |
| | |  | prompt_injection | 5 |  | | |
| | |  | pii | 3 |  | | |

### Risk bands (score → level)

`critical ≥ 90`, `high ≥ 70`, `medium ≥ 40`, `low ≥ 15`, else `none`.

These bands label the score; the **policy** thresholds (`block-critical-risk` at
85, `require-approval-elevated-risk` at 50 in the bundled set) decide the action.
Keep the two in mind together when tuning: moving a weight shifts which band and
which policy threshold a class of request lands in.

## Benchmarking the detectors

The design goal is *high recall on clearly-dangerous shapes, low false-positive
rate on benign developer activity*. A simple reproducible harness:

1. **Corpus.** Keep two labelled sets of synthetic requests — `dangerous` (what
   must reach `block`/`ask`) and `benign` (ordinary `ls`, `git`, project reads,
   safe writes that must stay `allow`). The unit tests in `tests/unit/` are the
   seed corpus; extend them.
2. **Run.** Feed each case through `SecurityEngine.evaluate` with the policy set
   under test (see `scripts/smoke_test.py` for the pattern) and record
   `decision`, `risk_score`, and `matched_rules`.
3. **Score.** Compute, per class:
   - recall on `dangerous` = fraction correctly *not* allowed,
   - false-positive rate on `benign` = fraction incorrectly `ask`/`block`,
   - and the score distribution per class to see how much headroom each band has.
4. **Tune.** Adjust a weight in `factors.py` or a pattern in `detection/`, re-run,
   and compare. Because scoring is additive and deterministic, every change is
   explainable and diffable — no retraining.

Report results alongside the exact policy file and the commit of `factors.py`
used, since both affect the outcome. And remember the hard ceiling on recall:
the detectors match *shapes*, so obfuscated/encoded/indirect payloads
(documented in [`limitations.md`](limitations.md)) will not be caught no matter
how the weights are tuned.
