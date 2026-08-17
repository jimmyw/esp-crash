"""Template rendering helpers. Mechanical move of server.py's custom
render_template wrapper, format_datetime filter, external_url_for, and the
chunked-transfer-encoding before_request hook. Adapted to use
flask.current_app instead of a module-global `app` (see app/auth.py for
why)."""
import hashlib

from flask import current_app, url_for, request
from sqlalchemy import func, select

from .auth import auth_filter
from .models import Crash, ProjectAuth, db


def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    return value.strftime(format)


# Dot colours for tag chips (see templates/_tags.html). Picked to stay
# distinguishable from each other against the chips' white background.
TAG_COLORS = (
    "#ef4444",  # red
    "#f97316",  # orange
    "#d97706",  # amber
    "#65a30d",  # lime
    "#16a34a",  # green
    "#0d9488",  # teal
    "#0891b2",  # cyan
    "#3b82f6",  # blue
    "#6366f1",  # indigo
    "#8b5cf6",  # violet
    "#c026d3",  # fuchsia
    "#db2777",  # pink
    "#bc8f8f",  # rosy brown
    "#64748b",  # slate
    "#a16207",  # dark yellow
    "#7c3aed",  # deep violet
)


def tag_color(name):
    """Pick a tag's dot colour from its name, so the same tag is always the
    same colour everywhere it is drawn, with no colour stored per tag.

    Hashed with md5 rather than the built-in hash(), which is salted per
    process (PYTHONHASHSEED) and would hand the same tag a different colour
    on every worker and every restart. Case- and whitespace-insensitive so
    "Backend" and "backend " land on one colour."""
    key = (name or "").strip().lower().encode("utf-8")
    return TAG_COLORS[int(hashlib.md5(key).hexdigest()[:8], 16) % len(TAG_COLORS)]


def external_url_for(endpoint, **values):
    """Generate external URL for Slack/webhook notifications.

    url_for() needs an active *request* context to build anything (a bare
    app_context isn't enough - it raises "Unable to build URLs outside an
    active request without 'SERVER_NAME' configured"). That's always been
    true during a real HTTP request (this app doesn't set SERVER_NAME), but
    cron_runner.py (see cron_runner.py/_tick) calls into cron() with only
    an app context, no request - so push a throwaway test_request_context
    to give url_for something to hang off regardless of which of those two
    ways we got here."""
    external_url = (current_app.config.get("EXTERNAL_URL") or "").rstrip('/')
    with current_app.test_request_context(base_url=external_url or None):
        if external_url:
            return f"{external_url}{url_for(endpoint, **values)}"
        return url_for(endpoint, _external=True, **values)


def render_template(template_name, **context):
    """Render a template with project list context."""
    crash_count = (
        select(func.count(Crash.crash_id))
        .where(Crash.project_name == ProjectAuth.project_name)
        .scalar_subquery()
        .label("crash_count")
    )
    stmt = (
        select(ProjectAuth.project_name, crash_count)
        .where(auth_filter(ProjectAuth.github))
        .order_by(ProjectAuth.project_name.asc())
    )
    projects = db.session.execute(stmt).mappings().all()
    return current_app.jinja_env.get_template(template_name).render(projects=projects, **context)


def handle_chunking():
    """
    Sets the "wsgi.input_terminated" environment flag, thus enabling
    Werkzeug to pass chunked requests as streams.  The gunicorn server
    should set this, but it's not yet been implemented.
    """
    transfer_encoding = request.headers.get("Transfer-Encoding", None)
    if transfer_encoding == u"chunked":
        request.environ["wsgi.input_terminated"] = True
