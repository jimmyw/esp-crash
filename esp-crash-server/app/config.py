"""Env-var driven app configuration. Mechanical move of server.py's
top-level config bootstrap (originally executed at import time) into a
function called once from create_app()."""
import os

from sqlalchemy.engine import URL


def database_uri():
    """Build the SQLAlchemy DB URL from the POSTGRES_* env vars, with the
    same defaults the app has always used (user esp-crash, port 5432, db
    esp-crash, sslmode prefer). Also imported by the Alembic env."""
    password = os.environ.get("POSTGRES_PASSWORD")
    password_file = os.environ.get("POSTGRES_PASSWORD_FILE")
    if not password and password_file:
        with open(password_file) as pf:
            password = pf.read().strip()
    return URL.create(
        "postgresql+psycopg2",
        username=os.environ.get("POSTGRES_USER", "esp-crash"),
        password=password,
        host=os.environ.get("POSTGRES_HOST", ""),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        database=os.environ.get("POSTGRES_DB", "esp-crash"),
        query={"sslmode": os.environ.get("POSTGRES_SSLMODE", "prefer")},
    )


def configure_app(app):
    app.secret_key = os.environ["APP_SECRET_KEY"]
    app.config['MAX_CONTENT_LENGTH'] = 64 * 1000 * 1000
    app.config["AUTH_TYPE"] = os.environ.get("AUTH_TYPE", "none").lower()
    if app.config["AUTH_TYPE"] not in ("none", "github"):
        raise ValueError("AUTH_TYPE must be either 'none' or 'github'")

    if app.config["AUTH_TYPE"] == "github":
        app.config["GITHUB_OAUTH_CLIENT_ID"] = os.environ["GITHUB_OAUTH_CLIENT_ID"]
        app.config["GITHUB_OAUTH_CLIENT_SECRET"] = os.environ["GITHUB_OAUTH_CLIENT_SECRET"]
    else:
        app.config["GITHUB_OAUTH_CLIENT_ID"] = ""
        app.config["GITHUB_OAUTH_CLIENT_SECRET"] = ""
    app.config["SLACK_CLIENT_ID"] = os.environ.get("SLACK_CLIENT_ID", "")
    app.config["SLACK_CLIENT_SECRET"] = os.environ.get("SLACK_CLIENT_SECRET", "")

    app.config["SQLALCHEMY_DATABASE_URI"] = database_uri()
    app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}

    # External URL configuration for Slack notifications
    app.config["EXTERNAL_URL"] = os.environ.get("EXTERNAL_URL", "")
    if not app.config["EXTERNAL_URL"]:
        app.logger.warning("EXTERNAL_URL not set - Slack URLs may not work properly")

    # Cron-driven AI summarize+tag step (app/ai_tagging.py). All optional -
    # cron.py requires every one of these to be set before attempting the
    # step; a missing/empty value cleanly skips it rather than retrying a
    # doomed API call every tick.
    app.config["ANTHROPIC_API_KEY"] = os.environ.get("ANTHROPIC_API_KEY", "")
    app.config["MCP_PUBLIC_URL"] = os.environ.get("MCP_PUBLIC_URL", "")
    app.config["MCP_SERVICE_TOKEN"] = os.environ.get("MCP_SERVICE_TOKEN", "")
    app.config["MCP_SERVICE_GITHUB_USER"] = os.environ.get("MCP_SERVICE_GITHUB_USER", "")
