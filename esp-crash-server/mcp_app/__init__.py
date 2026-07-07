"""esp-crash MCP server package.

Exposes esp-crash crash data + actions to MCP clients over Streamable HTTP,
authenticated with full OAuth (GitHub as the upstream identity provider) so
every tool call carries a GitHub identity and is scoped to that user's
projects - the same ACL model the web app enforces.

Layout:
- tools.py:  plain, ACL-scoped query/action functions (unit-testable).
- auth.py:   GitHub-backed OAuth authorization-server provider + token store.
- server.py: build_app() assembling the DB app + FastMCP resource server +
             OAuth routes into one ASGI app (imported by ../mcp_server.py).

Kept intentionally light so `from mcp_app import tools` doesn't pull in the
transport/OAuth stack (build_app() in server.py does that on demand).
"""
