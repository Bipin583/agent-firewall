# Releasing

Agent Firewall publishes to [PyPI](https://pypi.org) automatically when a
GitHub Release is published, via **Trusted Publishing (OIDC)** — no API token is
stored in the repository. The workflow is `.github/workflows/release.yml`.

## One-time PyPI setup (required before the first release)

Trusted Publishing lets GitHub Actions upload to PyPI without a long-lived
token, but PyPI has to be told which workflow to trust. This step needs a PyPI
account and can only be done by the project owner.

1. Sign in to <https://pypi.org>.
2. Go to **Your projects → Publishing** (or
   <https://pypi.org/manage/account/publishing/>).
3. Under **Add a new pending publisher**, enter:
   - **PyPI project name:** `agent-firewall`
   - **Owner:** `Bipin583`
   - **Repository name:** `agent-firewall`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
4. Save. (A "pending" publisher is fine — the project is created on first
   upload.)

Optionally create a matching GitHub **Environment** named `pypi`
(repo *Settings → Environments*) if you want required reviewers or other
protection rules on releases.

> For a dry run, you can instead target TestPyPI: add a pending publisher at
> <https://test.pypi.org> with the same values, and add
> `repository-url: https://test.pypi.org/legacy/` under the publish step's
> `with:`.

## Cutting a release

1. Bump `version` in `pyproject.toml` (SemVer) and move the `CHANGELOG.md`
   `[Unreleased]` section under the new version with today's date.
2. Make sure `main` is green (CI: ruff + mypy --strict + pytest).
3. Tag and publish a GitHub Release for the new version:

   ```bash
   git tag -a vX.Y.Z -m "Agent Firewall vX.Y.Z"
   git push origin vX.Y.Z
   gh release create vX.Y.Z --title "Agent Firewall vX.Y.Z" --notes "..."
   ```

4. Publishing the release triggers `release.yml`, which builds the sdist +
   wheel, runs `twine check`, and uploads to PyPI through Trusted Publishing.
5. Confirm the new version at <https://pypi.org/project/agent-firewall/>.

## Verifying a build locally

```bash
pip install build twine
python -m build
twine check dist/*
```
