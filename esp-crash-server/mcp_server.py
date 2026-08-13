"""ASGI entrypoint for the esp-crash MCP server.

Run with: uvicorn mcp_server:app --host 0.0.0.0 --port 8001
The MCP endpoint is served at /mcp; OAuth discovery/authorize/token/register
and the GitHub callback are mounted alongside it. See mcp_app/server.py.
"""
from mcp_app.server import build_app

app = build_app()
