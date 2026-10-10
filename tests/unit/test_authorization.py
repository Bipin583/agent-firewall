from __future__ import annotations

from agent_firewall.authorization import AuthorizationPolicy, is_known_tool
from agent_firewall.models import NormalizedRequest


def _req(tool: str, agent: str | None = None) -> NormalizedRequest:
    return NormalizedRequest(tool_name=tool, agent_id=agent)


def test_known_tools() -> None:
    assert is_known_tool("Bash")
    assert is_known_tool("mcp__memory__store")
    assert not is_known_tool("Frobnicate")


def test_unknown_tool_not_authorized_by_default() -> None:
    result = AuthorizationPolicy().check(_req("Frobnicate"))
    assert result.authorized is False
    assert any(f.rule_id == "authorization.unknown_tool" for f in result.findings)


def test_unknown_tool_can_be_explicitly_authorized() -> None:
    policy = AuthorizationPolicy(unknown_tool_authorized=True)
    result = policy.check(_req("Frobnicate"))
    assert result.authorized is True


def test_known_tool_authorized() -> None:
    assert AuthorizationPolicy().check(_req("Bash")).authorized is True


def test_agent_allowlist_blocks_disallowed_tool() -> None:
    policy = AuthorizationPolicy(agent_tool_allowlist={"agent-ro": {"Read"}})
    assert policy.check(_req("Read", agent="agent-ro")).authorized is True
    denied = policy.check(_req("Bash", agent="agent-ro"))
    assert denied.authorized is False
    assert any(f.rule_id == "authorization.tool_not_allowed" for f in denied.findings)


def test_agent_not_in_allowlist_is_unconstrained() -> None:
    policy = AuthorizationPolicy(agent_tool_allowlist={"other": {"Read"}})
    assert policy.check(_req("Bash", agent="free-agent")).authorized is True
