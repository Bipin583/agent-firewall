"""Normalization layer: raw tool payloads -> vendor-neutral ``NormalizedRequest``.

This is where tool-specific knowledge lives. For each supported tool we know
which argument is the "resource" and what action type it represents. Unknown
tools are normalised best-effort (resource/action unknown) and flagged later by
the authorization layer.

Keeping this isolated means adding a new integration = adding a mapping here,
without touching the engine.
"""

from __future__ import annotations

from typing import Any

from .models import ActionType, NormalizedRequest, TrustLevel

# tool_name -> (resource_arg_key, action_type)
_TOOL_MAP: dict[str, tuple[str | None, ActionType]] = {
    "Bash": ("command", ActionType.EXECUTE),
    "Read": ("file_path", ActionType.READ),
    "Write": ("file_path", ActionType.WRITE),
    "Edit": ("file_path", ActionType.WRITE),
    "MultiEdit": ("file_path", ActionType.WRITE),
    "NotebookEdit": ("notebook_path", ActionType.WRITE),
    "Glob": ("pattern", ActionType.READ),
    "Grep": ("pattern", ActionType.READ),
    "WebFetch": ("url", ActionType.NETWORK),
}


def _resource_for(tool_name: str, tool_input: dict[str, Any]) -> tuple[str | None, ActionType]:
    if tool_name in _TOOL_MAP:
        key, action = _TOOL_MAP[tool_name]
        resource = None
        if key is not None:
            val = tool_input.get(key)
            resource = val if isinstance(val, str) else None
        return resource, action
    if tool_name.startswith("mcp__"):
        # MCP tool: resource/action depend on the specific server. Best-effort:
        # pick a url/path-like arg if present; action unknown by default.
        for key in ("url", "path", "file_path", "query", "resource"):
            val = tool_input.get(key)
            if isinstance(val, str):
                action = ActionType.NETWORK if key == "url" else ActionType.UNKNOWN
                return val, action
    return None, ActionType.UNKNOWN


def normalize(
    tool_name: str,
    tool_input: dict[str, Any],
    *,
    session_id: str | None = None,
    agent_id: str | None = None,
    cwd: str | None = None,
    project_root: str | None = None,
    environment: str = "development",
    content_trust: TrustLevel = TrustLevel.UNKNOWN,
    provenance_refs: list[str] | None = None,
) -> NormalizedRequest:
    resource, action_type = _resource_for(tool_name, tool_input)
    return NormalizedRequest(
        tool_name=tool_name,
        tool_args=dict(tool_input),
        resource=resource,
        action_type=action_type,
        session_id=session_id,
        agent_id=agent_id,
        cwd=cwd,
        project_root=project_root,
        environment=environment,
        content_trust=content_trust,
        provenance_refs=provenance_refs or [],
        raw_tool_input=dict(tool_input),
    )
