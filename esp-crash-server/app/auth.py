"""Auth helpers: login_required plus the SQLAlchemy auth-filter family.
Uses flask.current_app instead of a module-global `app` reference (this
module is imported before any specific app instance exists - standard Flask
blueprint pattern; behavior is identical since there is always exactly one
app in a request context)."""
from functools import wraps

from apiflask import abort as api_abort
from flask import current_app, redirect, session, url_for
from flask_dance.contrib.github import github
from sqlalchemy import select, true

from .models import ProjectAuth


def github_auth_enabled():
    return current_app.config["AUTH_TYPE"] == "github"


def auth_filter(column=ProjectAuth.github):
    """A boolean ColumnElement to pass to .where(...). In no-auth mode it's
    the tautology TRUE (no filtering); under github auth it restricts to the
    current user's rows."""
    if github_auth_enabled():
        return column == session.get("gh_user")
    return true()


def auth_project_in_filter(project_column):
    """Restrict `project_column` to projects the current user has a
    project_auth row for (TRUE in no-auth mode)."""
    if github_auth_enabled():
        return project_column.in_(
            select(ProjectAuth.project_name).where(
                ProjectAuth.github == session.get("gh_user")
            )
        )
    return true()


def _resolve_gh_user():
    """Populate session["gh_user"] from GitHub OAuth (or the no-auth
    sentinel), the way login_required has always done it inline. Returns
    one of three states so each decorator below can respond the way that
    suits its caller (HTML redirect vs JSON), without this shared helper
    baking in either response format itself:

    - "ok": session["gh_user"] is set, proceed.
    - "unauthenticated": no valid GitHub OAuth session yet.
    - "github_error": GitHub OAuth token present but the /user API call
      itself failed - a genuine upstream failure, not a login prompt.
    """
    if current_app.config["AUTH_TYPE"] == "none":
        # Keep authorization checks and SQL filters working in no-auth mode.
        session.setdefault("gh_user", "none")
        return "ok"

    # If the app previously ran in no-auth mode, clear the sentinel value
    # so we can repopulate the real GitHub username after OAuth.
    if session.get("gh_user") == "none":
        session.pop("gh_user", None)

    if not github.authorized:
        return "unauthenticated"
    if "gh_user" not in session:
        resp = github.get("/user")
        if not resp.ok:
            return "github_error"
        session["gh_user"] = resp.json()["login"]
    return "ok"


def login_required(f):
    """Decorator to require GitHub authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        state = _resolve_gh_user()
        if state == "unauthenticated":
            return redirect(url_for("github.login"))
        if state == "github_error":
            return "Fail to auth github oauth", 500
        return f(*args, **kwargs)
    return decorated_function


def api_login_required(f):
    """Like login_required, but for JSON API routes: a fetch() caller can't
    usefully follow an OAuth redirect, so an unauthenticated request gets a
    401 JSON response instead (via apiflask.abort, so it comes back through
    app/api/errors.py's {"error": {...}} shape rather than an HTML page).
    AUTH_TYPE=none behaves identically to the HTML app (session
    gh_user="none" sentinel, no auth required)."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        state = _resolve_gh_user()
        if state == "unauthenticated":
            api_abort(401, message="Authentication required")
        if state == "github_error":
            api_abort(500, message="Fail to auth github oauth")
        return f(*args, **kwargs)
    return decorated_function
