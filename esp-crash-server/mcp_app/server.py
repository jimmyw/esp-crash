"""Assemble the esp-crash MCP server into one ASGI app.

build_app() wires:
- a minimal Flask app whose only job is to own the SQLAlchemy engine/session
  (reusing app/config.py:database_uri() + app/models.py:db), so the tool
  functions can run inside an app context;
- a FastMCP resource server whose bearer tokens are issued/verified by the
  GitHub-backed OAuth provider (mcp_app/auth.py) - passing auth_server_provider
  makes streamable_http_app() also mount the AS endpoints (/authorize, /token,
  /register, /revoke, and the discovery metadata);
- @mcp.tool wrappers that resolve the caller's GitHub username from the access
  token and delegate to the ACL-scoped functions in tools.py;
- a /github/callback custom route completing the upstream OAuth exchange.

Served by uvicorn via ../mcp_server.py.
"""
import os

from flask import Flask
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

from app.config import database_uri
from app.models import db

from . import tools
from .auth import GitHubOAuthProvider

MCP_SCOPE = os.environ.get("MCP_SCOPE", "esp-crash")


def _require_env(name):
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be set for the MCP server")
    return value


def _make_db_app():
    """A bare Flask app that only owns the DB session (no routes/blueprints)."""
    flask_app = Flask("esp_crash_mcp_db")
    flask_app.config["SQLALCHEMY_DATABASE_URI"] = database_uri()
    flask_app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
    db.init_app(flask_app)
    return flask_app


def build_app():
    public_url = _require_env("MCP_PUBLIC_URL").rstrip("/")
    github_client_id = _require_env("GITHUB_OAUTH_CLIENT_ID")
    github_client_secret = _require_env("GITHUB_OAUTH_CLIENT_SECRET")

    flask_app = _make_db_app()

    provider = GitHubOAuthProvider(
        flask_app=flask_app,
        github_client_id=github_client_id,
        github_client_secret=github_client_secret,
        callback_url=f"{public_url}/github/callback",
        mcp_scope=MCP_SCOPE,
        service_token=os.environ.get("MCP_SERVICE_TOKEN"),
        service_github_user=os.environ.get("MCP_SERVICE_GITHUB_USER"),
    )

    mcp = FastMCP(
        name="esp-crash",
        instructions="Query and manage ESP32 crash reports, projects, and builds. "
        "Every tool is scoped to the projects your GitHub account has access to.",
        host="0.0.0.0",
        port=int(os.environ.get("MCP_PORT", "8001")),
        stateless_http=True,
        json_response=True,
        auth_server_provider=provider,
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(public_url),
            resource_server_url=AnyHttpUrl(public_url),
            required_scopes=[MCP_SCOPE],
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=[MCP_SCOPE],
                default_scopes=[MCP_SCOPE],
            ),
        ),
    )

    def _current_user() -> str:
        token: AccessToken | None = get_access_token()
        if token is None or not token.subject:
            raise ValueError("Not authenticated")
        return token.subject

    # ---- read tools -------------------------------------------------------

    @mcp.tool()
    def list_projects() -> list[dict]:
        """List the projects you can access, each with its crash count."""
        with flask_app.app_context():
            return tools.list_projects(_current_user())

    @mcp.tool()
    def list_crashes(
        project_name: str | None = None,
        search: str | None = None,
        tag_id: int | None = None,
        signature: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """List crashes across your projects (newest first). Optionally filter
        by project_name, a full-text search string, tag_id (see list_tags for
        a project's available tag_ids), and/or signature - a non-AI
        duplicate-grouping fingerprint each crash carries; pass another
        crash's `signature` field (from list_crashes/get_crash) to find every
        crash with the same likely root cause, the same thing the web UI's
        "Related" link does."""
        with flask_app.app_context():
            return tools.list_crashes(_current_user(), project_name, search, tag_id, signature, limit, offset)

    @mcp.tool()
    def get_crash(crash_id: int) -> dict | None:
        """Get full detail for one crash, including the symbolicated dump, the
        ELF builds available for its project/version, and its `signature` (a
        non-AI duplicate-grouping fingerprint - pass it to list_crashes to
        find related crashes). Null if not found or not accessible to you."""
        with flask_app.app_context():
            return tools.get_crash(_current_user(), crash_id)

    @mcp.tool()
    def list_builds(project_name: str) -> list[dict]:
        """List the uploaded ELF builds for one of your projects."""
        with flask_app.app_context():
            return tools.list_builds(_current_user(), project_name)

    @mcp.tool()
    def get_build(build_id: int) -> dict | None:
        """Get detail for one uploaded ELF build. Null if not found/accessible."""
        with flask_app.app_context():
            return tools.get_build(_current_user(), build_id)

    @mcp.tool()
    def list_tags(project_name: str) -> list[dict]:
        """List the tags defined for one of your projects (e.g. reviewed,
        wontfix, duplicate), for picking an existing one before calling
        add_tag_to_crash."""
        with flask_app.app_context():
            return tools.list_tags(_current_user(), project_name)

    # ---- action tools -----------------------------------------------------

    @mcp.tool()
    def refresh_crash(crash_id: int) -> dict:
        """Clear a crash's cached dump so the cron worker re-symbolicates it."""
        with flask_app.app_context():
            return tools.refresh_crash(_current_user(), crash_id)

    @mcp.tool()
    def delete_crash(crash_id: int) -> dict:
        """Permanently delete one of your crashes."""
        with flask_app.app_context():
            return tools.delete_crash(_current_user(), crash_id)

    @mcp.tool()
    def delete_build(build_id: int) -> dict:
        """Permanently delete one of your uploaded ELF builds."""
        with flask_app.app_context():
            return tools.delete_build(_current_user(), build_id)

    @mcp.tool()
    def set_build_alias(build_id: int, alias: str) -> dict:
        """Set the alias for one of your uploaded ELF builds."""
        with flask_app.app_context():
            return tools.set_build_alias(_current_user(), build_id, alias)

    @mcp.tool()
    def set_device_alias(device_id: int, alias: str) -> dict:
        """Set the alias for a device that has appeared in a crash under one
        of your projects."""
        with flask_app.app_context():
            return tools.set_device_alias(_current_user(), device_id, alias)

    @mcp.tool()
    def create_project(project_name: str) -> dict:
        """Create a new project owned by your GitHub account."""
        with flask_app.app_context():
            return tools.create_project(_current_user(), project_name)

    @mcp.tool()
    def add_tag_to_crash(crash_id: int, tag_name: str, tag_description: str | None = None) -> dict:
        """Attach a tag to a crash. Creates the tag for that crash's project
        if tag_name isn't already one of its tags (names are case-folded);
        tag_description is only used when creating a new tag."""
        with flask_app.app_context():
            return tools.add_tag_to_crash(_current_user(), crash_id, tag_name, tag_description)

    @mcp.tool()
    def remove_tag_from_crash(crash_id: int, tag_id: int) -> dict:
        """Detach a tag from a crash (the tag itself is left intact for reuse)."""
        with flask_app.app_context():
            return tools.remove_tag_from_crash(_current_user(), crash_id, tag_id)

    # ---- upstream GitHub OAuth callback -----------------------------------

    @mcp.custom_route("/github/callback", methods=["GET"])
    async def github_callback(request):
        return await provider.handle_github_callback(request)

    return mcp.streamable_http_app()
