"""Env-var driven app configuration. Mechanical move of server.py's
top-level config bootstrap (originally executed at import time) into a
function called once from create_app()."""
import os


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

    # External URL configuration for Slack notifications
    app.config["EXTERNAL_URL"] = os.environ.get("EXTERNAL_URL", "")
    if not app.config["EXTERNAL_URL"]:
        app.logger.warning("EXTERNAL_URL not set - Slack URLs may not work properly")
