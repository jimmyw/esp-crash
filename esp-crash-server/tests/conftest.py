"""Shared pytest fixtures for the esp-crash-server characterization suite.

Scoped to this directory (not the esp-crash-server root) so these Docker/DB
fixtures - especially the autouse db_clean truncate - only apply to the
Flask route tests here, not to the pre-existing pure-logic tests at the repo
root (test_decode_module_coredump.py, test_device_url.py), which have no
Postgres/Docker dependency and shouldn't gain one.

Every fixture here runs against a throwaway Postgres instance. By default
that's an ephemeral testcontainers-managed `postgres:15` container, fully
separate from the real docker-compose stack this machine also runs (its own
container, its own network, torn down at the end of the test session). Point
POSTGRES_TEST_DSN at some other disposable Postgres you control if you'd
rather not use Docker for the test DB — never at the production instance.
"""
import os

import psycopg2
import pytest

# esp-crash-server root, one directory up from tests/.
_SERVER_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_schema():
    """Build the test DB schema by running the Alembic migrations to head -
    the same path a real install now uses - so the suite validates that the
    migrations reproduce the schema the routes expect. Reads the DB URL from
    the POSTGRES_* env vars the caller has already exported."""
    from alembic import command
    from alembic.config import Config

    cfg = Config(os.path.join(_SERVER_ROOT, "alembic.ini"))
    cfg.set_main_option("script_location", os.path.join(_SERVER_ROOT, "alembic"))
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
def _pg():
    """Provision a throwaway Postgres for the whole test session and export
    its connection params via POSTGRES_* env vars (what server.py reads)."""
    dsn_override = os.environ.get("POSTGRES_TEST_DSN")
    if dsn_override:
        # Developer-provided disposable instance. Never the production one.
        import urllib.parse as up

        parsed = up.urlparse(dsn_override)
        os.environ["POSTGRES_HOST"] = parsed.hostname or "localhost"
        os.environ["POSTGRES_PORT"] = str(parsed.port or 5432)
        os.environ["POSTGRES_USER"] = parsed.username or "esp-crash"
        os.environ["POSTGRES_PASSWORD"] = parsed.password or ""
        os.environ["POSTGRES_DB"] = (parsed.path or "/esp-crash").lstrip("/")
        os.environ["POSTGRES_SSLMODE"] = "disable"
        _load_schema()
        yield dsn_override
        return

    from testcontainers.postgres import PostgresContainer

    with PostgresContainer(
        "postgres:15", username="esp-crash", password="esp-crash", dbname="esp-crash"
    ) as pg:
        host = pg.get_container_host_ip()
        # Force IPv4: "localhost" resolves to ::1 first on some Docker setups
        # (e.g. userland-proxy disabled + custom nftables rules), and the
        # published port isn't reachable over IPv6 there - every connection
        # then eats a long OS-level TCP timeout on ::1 before falling back
        # to 127.0.0.1. Skip the ambiguous hostname entirely.
        if host in ("localhost", "127.0.0.1", "::1"):
            host = "127.0.0.1"
        port = pg.get_exposed_port(5432)
        os.environ["POSTGRES_HOST"] = host
        os.environ["POSTGRES_PORT"] = str(port)
        os.environ["POSTGRES_USER"] = "esp-crash"
        os.environ["POSTGRES_PASSWORD"] = "esp-crash"
        os.environ["POSTGRES_DB"] = "esp-crash"
        os.environ["POSTGRES_SSLMODE"] = "disable"
        dsn = f"postgresql://esp-crash:esp-crash@{host}:{port}/esp-crash"
        _load_schema()
        yield dsn


@pytest.fixture(scope="session")
def server_module(_pg):
    """Import server.py against the throwaway DB, once per session."""
    os.environ.setdefault("APP_SECRET_KEY", "test-secret-key")
    os.environ.setdefault("AUTH_TYPE", "none")

    import server as server_module

    server_module.app.config["TESTING"] = True
    return server_module


@pytest.fixture(scope="session")
def _admin_conn(_pg):
    conn = psycopg2.connect(_pg)
    conn.autocommit = True
    yield conn
    conn.close()


TABLES_TO_TRUNCATE = (
    "device",
    "crash",
    "crash_relation_tag",
    "crash_relation",
    "tag",
    "elf_file",
    "project_auth",
    "project_webhooks",
    "project_slack_integrations",
    "project_settings",
    "module_elf",
    "mcp_oauth_client",
    "mcp_access_token",
    "mcp_refresh_token",
)


@pytest.fixture(autouse=True)
def db_clean(server_module, _admin_conn):
    """Truncate all tables after every test for isolation.

    Release the SQLAlchemy connection back to the pool first (ending any
    transaction a SELECT-only request left open) so it can't hold an
    AccessShareLock that would deadlock the TRUNCATE below.
    """
    yield
    from app.models import db as sa_db

    with server_module.app.app_context():
        sa_db.session.remove()

    with _admin_conn.cursor() as cur:
        cur.execute(
            "TRUNCATE " + ", ".join(TABLES_TO_TRUNCATE) + " RESTART IDENTITY CASCADE;"
        )


@pytest.fixture
def db_conn(_admin_conn):
    """Raw psycopg2 connection for seeding/asserting DB state directly."""
    return _admin_conn


@pytest.fixture
def app(server_module):
    return server_module.app


@pytest.fixture
def client(app):
    app.config["AUTH_TYPE"] = "none"
    return app.test_client()


@pytest.fixture
def github_auth_unauthenticated(server_module, monkeypatch):
    """AUTH_TYPE=github with no GitHub token - login_required should redirect
    to the OAuth login view."""
    from app import auth as auth_module

    app = server_module.app
    monkeypatch.setitem(app.config, "AUTH_TYPE", "github")
    monkeypatch.setattr(auth_module, "github", _FakeGithub(authorized=False))
    return app.test_client()


@pytest.fixture
def github_client(server_module, monkeypatch):
    """Factory: a test client authenticated as a fake GitHub user under
    AUTH_TYPE=github, with a project_auth-seedable session["gh_user"]."""
    from app import auth as auth_module

    app = server_module.app

    def _login_as(username):
        monkeypatch.setitem(app.config, "AUTH_TYPE", "github")
        monkeypatch.setattr(auth_module, "github", _FakeGithub(username=username))
        client = app.test_client()
        with client.session_transaction() as sess:
            sess["gh_user"] = username
        return client

    return _login_as


class _FakeGithub:
    """Stand-in for flask_dance's `github` LocalProxy, swapped into
    app/auth.py's module namespace so login_required's `github.authorized` /
    `github.get(...)` calls never hit the network."""

    def __init__(self, authorized=True, username=None):
        self.authorized = authorized
        self._username = username

    def get(self, path):
        return _FakeGithubResponse({"login": self._username})


class _FakeGithubResponse:
    def __init__(self, payload):
        self.ok = True
        self._payload = payload

    def json(self):
        return self._payload
