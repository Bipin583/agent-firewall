# Security Policy

## Supported versions

Agent Firewall is pre-1.0. Security fixes are applied to the latest release and
the `main` branch.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌        |

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the [**Security** tab](https://github.com/Bipin583/agent-firewall/security) of the repository.
2. Click **Report a vulnerability** and fill in the advisory form.

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal policy + request payload is ideal),
- the version / commit you tested, and
- any suggested remediation.

You can expect an initial acknowledgement within a few days. Once a fix is
ready, we will coordinate disclosure and credit you in the advisory unless you
prefer to remain anonymous.

## Scope and threat model

Agent Firewall is a **policy gate, not a sandbox** — it evaluates described tool
requests and returns `allow` / `ask` / `block`, but it never executes the tool
it is judging and only reasons about what the integration hands it. Before
relying on it, read [`docs/limitations.md`](docs/limitations.md) for the honest
threat model and known gaps.

Reports that are especially in scope:

- a crafted request or policy that makes the engine **fail open** (returns
  `allow` where it should `ask`/`block`), or crashes it in a way an integration
  would treat as allow,
- a detector or normalizer bypass (e.g. a destructive command or secret egress
  that scores far lower than intended),
- audit-log integrity issues (a tamper that `audit verify` fails to detect),
- authentication bypass on the HTTP API (`[api]` extra).
