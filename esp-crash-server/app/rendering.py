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
    """Generate external URL for Slack notifications."""
    external_url = current_app.config.get("EXTERNAL_URL")
    if external_url:
        # Remove trailing slash from external URL
        external_url = external_url.rstrip('/')
        # Generate the path using url_for
        with current_app.app_context():
            path = url_for(endpoint, **values)
        return f"{external_url}{path}"
    else:
        # Fallback to regular url_for with _external=True
        with current_app.app_context():
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
