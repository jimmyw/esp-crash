"""Template rendering helpers. Mechanical move of server.py's custom
render_template wrapper, format_datetime filter, external_url_for, and the
chunked-transfer-encoding before_request hook. Adapted to use
flask.current_app instead of a module-global `app` (see app/auth.py for
why)."""
from flask import current_app, url_for, request
from sqlalchemy import func, select

from .auth import auth_filter
from .models import Crash, ProjectAuth, db


def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    return value.strftime(format)


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
