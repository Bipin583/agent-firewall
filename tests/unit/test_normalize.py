from __future__ import annotations

from agent_firewall.models import ActionType, TrustLevel
from agent_firewall.normalize import normalize


def test_known_tools_map_resource_and_action() -> None:
    r = normalize("Bash", {"command": "ls"})
    assert r.resource == "ls"
    assert r.action_type is ActionType.EXECUTE

    w = normalize("Write", {"file_path": "a.py", "content": "x"})
    assert w.resource == "a.py"
    assert w.action_type is ActionType.WRITE

    read = normalize("Read", {"file_path": "a.py"})
    assert read.action_type is ActionType.READ


def test_non_string_resource_arg_becomes_none() -> None:
    r = normalize("Read", {"file_path": 123})
    assert r.resource is None


def test_unknown_tool_is_unknown_action() -> None:
    r = normalize("Frobnicate", {"x": 1})
    assert r.resource is None
    assert r.action_type is ActionType.UNKNOWN


def test_mcp_tool_url_is_network() -> None:
    r = normalize("mcp__http__fetch", {"url": "https://example.com"})
    assert r.resource == "https://example.com"
    assert r.action_type is ActionType.NETWORK


def test_mcp_tool_path_is_unknown_action() -> None:
    r = normalize("mcp__fs__read", {"path": "/tmp/x"})
    assert r.resource == "/tmp/x"
    assert r.action_type is ActionType.UNKNOWN


def test_passthrough_context_fields() -> None:
    r = normalize(
        "Read",
        {"file_path": "a"},
        session_id="s1",
        agent_id="agent-a",
        environment="production",
        content_trust=TrustLevel.EXTERNAL_DOCUMENT,
        provenance_refs=["doc://1"],
    )
    assert r.session_id == "s1"
    assert r.agent_id == "agent-a"
    assert r.environment == "production"
    assert r.content_trust is TrustLevel.EXTERNAL_DOCUMENT
    assert r.provenance_refs == ["doc://1"]
    # raw_tool_input is preserved for evaluation.
    assert r.raw_tool_input == {"file_path": "a"}
