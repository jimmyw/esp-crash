"""Auth helpers. Mechanical move of server.py's login_required/auth_clause
family, adapted to use flask.current_app instead of a module-global `app`
reference (needed now that this module is imported before any specific app
instance exists - standard Flask blueprint pattern, behavior is identical
since there is always exactly one app in a request context)."""
from functools import wraps

from flask import current_app, redirect, session, url_for
from flask_dance.contrib.github import github
from sqlalchemy import select, true

from .models import ProjectAuth


def github_auth_enabled():
    return current_app.config["AUTH_TYPE"] == "github"


def auth_clause(column_name="project_auth.github"):
    if github_auth_enabled():
        return f"{column_name} = %s", (session.get("gh_user"),)
    return "TRUE", ()


def auth_project_in_clause(project_column="project_name"):
    if github_auth_enabled():
        return f"{project_column} IN (SELECT project_name FROM project_auth WHERE github = %s)", (session.get("gh_user"),)
    return "TRUE", ()


def auth_filter(column=ProjectAuth.github):
    """SQLAlchemy equivalent of auth_clause: a boolean ColumnElement to pass
    to .where(...). In no-auth mode it's the tautology TRUE (no filtering);
    under github auth it restricts to the current user's rows."""
    if github_auth_enabled():
        return column == session.get("gh_user")
    return true()


def auth_project_in_filter(project_column):
    """SQLAlchemy equivalent of auth_project_in_clause: restrict `project_column`
    to projects the current user has a project_auth row for."""
    if github_auth_enabled():
        return project_column.in_(
            select(ProjectAuth.project_name).where(
                ProjectAuth.github == session.get("gh_user")
            )
        )
    return true()


def login_required(f):
    """Decorator to require GitHub authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_app.config["AUTH_TYPE"] == "none":
            # Keep authorization checks and SQL filters working in no-auth mode.
            session.setdefault("gh_user", "none")
            return f(*args, **kwargs)

        # If the app previously ran in no-auth mode, clear the sentinel value
        # so we can repopulate the real GitHub username after OAuth.
        if session.get("gh_user") == "none":
            session.pop("gh_user", None)

        if not github.authorized:
            return redirect(url_for("github.login"))
        if "gh_user" not in session:
            resp = github.get("/user")
            if not resp.ok:
                return "Fail to auth github oauth", 500
            session["gh_user"] = resp.json()["login"]
        return f(*args, **kwargs)
    return decorated_function
