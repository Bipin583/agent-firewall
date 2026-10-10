#!/usr/bin/env python3
"""Thin entry point invoked by Claude Code as a PreToolUse hook.

Claude Code runs this with the hook JSON on stdin. We keep this file tiny and let
it locate the package in ``src/`` so the repo works without being pip-installed.
If the package *is* installed, the sys.path insert is harmless.

All real logic lives in agent_firewall.integrations.claude_code.hook.
"""

from __future__ import annotations

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(os.path.dirname(_HERE), "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

try:
    from agent_firewall.integrations.claude_code.hook import main
except Exception as exc:  # pragma: no cover - import-time failure must fail safe
    # If we cannot even import the firewall, surface an "ask" so the human decides
    # rather than silently allowing the operation.
    import json

    sys.stdout.write(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "ask",
                    "permissionDecisionReason": f"Agent Firewall failed to load: {exc}",
                }
            }
        )
    )
    raise SystemExit(0) from exc

if __name__ == "__main__":
    raise SystemExit(main())
