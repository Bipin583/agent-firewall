"""Optional HTTP API for Agent Firewall.

Imported only when the ``[api]`` extra is installed. Nothing in the core engine
or the Claude Code hook depends on this package.
"""

from .app import create_app

__all__ = ["create_app"]
