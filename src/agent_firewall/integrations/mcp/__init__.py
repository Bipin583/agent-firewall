"""MCP gateway for the Agent Firewall (optional ``[mcp]`` extra)."""

from __future__ import annotations

from .server import TOOL_NAME, build_server, evaluate_tool_request, run

__all__ = ["TOOL_NAME", "build_server", "evaluate_tool_request", "run"]
