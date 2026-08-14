"""Tests for mcp_app/auth.py's DB-backed OAuth client/token storage.

Each test constructs GitHubOAuthProvider directly (no HTTP transport) against
the `app` fixture's Flask app, which already owns a SQLAlchemy session for
the throwaway test DB - exactly the object mcp_app/server.py passes in as
flask_app. Provider methods are async (the SDK's protocol requires it), so
they're driven with asyncio.run() rather than pytest-asyncio (not a project
dependency).
"""
import asyncio
import time

from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from mcp_app.auth import GitHubOAuthProvider


def _run(coro):
    return asyncio.run(coro)


def _provider(app):
    return GitHubOAuthProvider(
        flask_app=app,
        github_client_id="gh-client-id",
        github_client_secret="gh-client-secret",
        callback_url="https://mcp.example/github/callback",
    )


def test_register_client_persists_across_provider_instances(app, db_conn):
    client_info = OAuthClientInformationFull(
        client_id="client-abc",
        client_secret="secret-abc",
        redirect_uris=["http://localhost:12345/callback"],
    )
    _run(_provider(app).register_client(client_info))

    # A fresh instance stands in for a restarted `mcp` container/process -
    # the whole point is that this must NOT be an empty in-memory dict.
    loaded = _run(_provider(app).get_client("client-abc"))
    assert loaded is not None
    assert loaded.client_id == "client-abc"
    assert loaded.client_secret == "secret-abc"
    assert str(loaded.redirect_uris[0]) == "http://localhost:12345/callback"


def test_get_client_missing_returns_none(app, db_conn):
    assert _run(_provider(app).get_client("nope")) is None


def test_issued_access_token_persists_and_loads(app, db_conn):
    provider = _provider(app)
    token = provider._issue_tokens(client_id="client-1", scopes=["esp-crash"], subject="alice")

    # Simulate a restart: new provider instance, same DB.
    loaded = _run(_provider(app).load_access_token(token.access_token))
    assert loaded is not None
    assert loaded.client_id == "client-1"
    assert loaded.subject == "alice"
    assert loaded.scopes == ["esp-crash"]


def test_load_access_token_expired_is_purged(app, db_conn):
    provider = _provider(app)
    with app.app_context():
        from app.models import McpAccessToken, db as sa_db

        sa_db.session.add(McpAccessToken(
            token="expired-tok", client_id="client-1", expires_at=int(time.time()) - 10,
            data=AccessToken(
                token="expired-tok", client_id="client-1", scopes=["esp-crash"],
                expires_at=int(time.time()) - 10, subject="alice",
            ).model_dump(mode="json"),
        ))
        sa_db.session.commit()

    assert _run(provider.load_access_token("expired-tok")) is None

    with app.app_context():
        from app.models import McpAccessToken, db as sa_db

        assert sa_db.session.get(McpAccessToken, "expired-tok") is None


def test_load_access_token_service_token_short_circuits_without_db(app, db_conn):
    provider = GitHubOAuthProvider(
        flask_app=app,
        github_client_id="gh-client-id",
        github_client_secret="gh-client-secret",
        callback_url="https://mcp.example/github/callback",
        service_token="svc-secret",
        service_github_user="esp-crash-bot",
    )
    loaded = _run(provider.load_access_token("svc-secret"))
    assert loaded is not None
    assert loaded.client_id == "service"
    assert loaded.subject == "esp-crash-bot"


def test_refresh_token_exchange_rotates_and_persists(app, db_conn):
    provider = _provider(app)
    issued = provider._issue_tokens(client_id="client-1", scopes=["esp-crash"], subject="alice")

    class _Client:
        client_id = "client-1"

    old_refresh = _run(provider.load_refresh_token(_Client(), issued.refresh_token))
    assert old_refresh is not None

    new_tokens = _run(provider.exchange_refresh_token(_Client(), old_refresh, ["esp-crash"]))
    assert new_tokens.access_token != issued.access_token
    assert new_tokens.refresh_token != issued.refresh_token

    # Old refresh token is gone (single use); a fresh provider instance
    # confirms this isn't just an in-memory pop.
    assert _run(_provider(app).load_refresh_token(_Client(), issued.refresh_token)) is None
    # The new access token is loadable, including after a simulated restart.
    assert _run(_provider(app).load_access_token(new_tokens.access_token)) is not None


def test_revoke_token_removes_access_and_refresh_rows(app, db_conn):
    provider = _provider(app)
    issued = provider._issue_tokens(client_id="client-1", scopes=["esp-crash"], subject="alice")

    _run(provider.revoke_token(AccessToken(
        token=issued.access_token, client_id="client-1", scopes=["esp-crash"], subject="alice",
    )))
    assert _run(_provider(app).load_access_token(issued.access_token)) is None

    class _Client:
        client_id = "client-1"

    _run(provider.revoke_token(RefreshToken(
        token=issued.refresh_token, client_id="client-1", scopes=["esp-crash"], subject="alice",
    )))
    assert _run(_provider(app).load_refresh_token(_Client(), issued.refresh_token)) is None
