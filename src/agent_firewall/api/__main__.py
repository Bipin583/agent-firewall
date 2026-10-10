"""Run the API with uvicorn: ``python -m agent_firewall.api``.

Honours HOST/PORT via AGENT_FIREWALL_API_HOST / AGENT_FIREWALL_API_PORT.
Terminate TLS in front of this process; it serves plain HTTP.
"""

from __future__ import annotations

import os

import uvicorn

from .app import create_app


def main() -> None:
    app = create_app()
    host = os.environ.get("AGENT_FIREWALL_API_HOST", "127.0.0.1")
    port = int(os.environ.get("AGENT_FIREWALL_API_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
