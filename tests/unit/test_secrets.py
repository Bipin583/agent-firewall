from __future__ import annotations

from agent_firewall.detection.secrets import (
    contains_secret,
    redact,
    scan_text,
    scrub,
)

# Synthetic secrets assembled at runtime so this file contains no literal
# credential-shaped string (the firewall hook would otherwise flag the Write).
AWS_KEY = "AKIA" + "IOSFODNN7EXAMPLE"
PRIV_HDR = "-----BEGIN RSA " + "PRIVATE KEY-----"
GH_TOKEN = "ghp_" + "A" * 36
ANT_KEY = "sk-ant-" + "A" * 24


def _ids(text: str) -> set[str]:
    return {f.rule_id for f in scan_text(text)}


def test_detects_common_secret_shapes() -> None:
    assert "secret.aws_access_key" in _ids(f"key {AWS_KEY} here")
    assert "secret.github_token" in _ids(GH_TOKEN)
    assert "secret.private_key_header" in _ids(PRIV_HDR)
    assert "secret.anthropic_key" in _ids(ANT_KEY)


def test_benign_text_has_no_secret_findings() -> None:
    assert not any(
        f.category == "secret" for f in scan_text("just some ordinary prose, nothing to see")
    )


def test_evidence_is_always_redacted() -> None:
    findings = scan_text(f"token={AWS_KEY}")
    aws = [f for f in findings if f.rule_id == "secret.aws_access_key"][0]
    assert AWS_KEY not in (aws.evidence or "")
    assert "****" in (aws.evidence or "")


def test_redact_keeps_short_prefix_only() -> None:
    assert redact("abcdefghij", keep=4) == "abcd******"
    assert redact("ab") == "**"


def test_contains_secret_vs_pii() -> None:
    assert contains_secret(AWS_KEY)
    # An email is PII, not a secret -> contains_secret stays False.
    assert not contains_secret("reach me at dev@example.com")


def test_scrub_masks_secrets_but_leaves_pii_readable() -> None:
    text = f"key {AWS_KEY} and mail dev@example.com"
    scrubbed = scrub(text)
    assert AWS_KEY not in scrubbed
    assert "dev@example.com" in scrubbed  # PII intentionally not scrubbed


def test_one_finding_per_pattern_no_flood() -> None:
    # Many emails -> at most one pii.email finding.
    text = " ".join(f"user{i}@example.com" for i in range(20))
    emails = [f for f in scan_text(text) if f.rule_id == "pii.email"]
    assert len(emails) == 1
