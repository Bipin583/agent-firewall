# Contributing

Thanks for your interest in improving Agent Firewall.

## Development setup

Requires Python ≥ 3.11.

```bash
pip install -e ".[dev,api,mcp]"
```

## Before you open a pull request

Run the full quality gate — the same one CI enforces on Python 3.11 and 3.12:

```bash
python -m ruff check .     # lint
python -m mypy             # strict type-check
python -m pytest           # tests
python scripts/smoke_test.py   # end-to-end sanity check
```

All four must be green. New behavior needs tests, and public functions should
keep full type annotations (the project is `mypy --strict` clean).

## Guidelines

- **Security-critical ordering.** The engine pipeline (authorization →
  detection → risk → policy → combine) and its `deny > approval > allow`
  precedence are the heart of the project. Changes there need tests that show a
  request cannot *fail open*.
- **Keep the core dependency-light.** The core engine depends only on `pydantic`
  and `PyYAML`. New third-party dependencies belong behind an optional extra
  (like `[api]` and `[mcp]`), imported lazily.
- **Adding a tool integration?** Add its mapping in `normalize.py`; you should
  not need to touch the engine.
- **Use synthetic data.** Tests and fixtures must use synthetic credentials and
  safe, non-executed command strings only.

## Reporting security issues

Please do **not** use public issues for vulnerabilities — see
[`SECURITY.md`](SECURITY.md).
