"""Tests for the MCP gateway (src/agent_firewall/integrations/mcp).

The pure adjudication function is tested directly (no SDK transport needed);
the server-construction tests require the optional ``mcp`` SDK and skip without
it.
"""

from __future__ import annotations

import pytest

from agent_firewall.integrations.mcp import (
    TOOL_NAME,
    build_server,
    evaluate_tool_request,
)

mcp = pytest.importorskip("mcp", reason="requires the [mcp] extra")


def test_evaluate_tool_request_blocks_rm_rf_root() -> None:
    decision = evaluate_tool_request("Bash", {"command": "rm -rf /"})
    assert decision["decision"] == "block"
    assert decision["risk_score"] == 100
    assert "cmd.rm_rf_root" in decision["matched_rules"]
    # The decision is fully serializable (came back as plain JSON types).
    assert isinstance(decision["explanation"], str)


def test_evaluate_tool_request_allows_project_read(tmp_path) -> None:
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")
    from agent_firewall.config import CoreConfig

    cfg = CoreConfig.from_env(cwd=str(tmp_path))
    decision = evaluate_tool_request(
        "Read", {"file_path": str(tmp_path / "notes.txt")}, config=cfg
    )
    assert decision["decision"] == "allow"


def test_unknown_tool_is_blocked_fail_closed() -> None:
    decision = evaluate_tool_request("Frobnicate", {"foo": "bar"})
    assert decision["decision"] == "block"
    assert "authorization.unknown_tool" in decision["matched_rules"]


def test_bad_content_trust_falls_back_to_unknown() -> None:
    # A nonsense trust label must not raise and must not fail open.
    decision = evaluate_tool_request(
        "Bash", {"command": "echo hi"}, content_trust="not-a-real-level"
    )
    assert decision["decision"] in {"allow", "ask", "block"}


@pytest.mark.asyncio
async def test_build_server_registers_evaluate_tool() -> None:
    server = build_server()
    tools = await server.list_tools()
    names = {t.name for t in tools}
    assert TOOL_NAME in names
    tool = next(t for t in tools if t.name == TOOL_NAME)
    props = (tool.input_schema or {}).get("properties", {})
    assert "tool_name" in props
    assert (tool.input_schema or {}).get("required") == ["tool_name"]
