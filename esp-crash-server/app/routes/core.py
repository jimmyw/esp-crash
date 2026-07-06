"""Health check, dashboard, settings, and landing page. Mechanical move from
server.py - routes and logic unchanged, endpoint names preserved exactly
(these are registered directly on the app object, not via Flask Blueprint,
because Blueprint.add_url_rule always prefixes endpoint names with the
blueprint's name - which would break every url_for() call in the existing
templates)."""
from ..auth import login_required
from ..rendering import render_template


def health():
    """Kubernetes liveness/readiness probe endpoint."""
    return "", 200


@login_required
def dashboard():
    """Render the user dashboard."""
    return render_template('dashboard.html')


@login_required
def settings():
    """Render the account settings page."""
    return render_template('settings.html')


@login_required
def list_projects():
    """Render the landing page listing all projects."""
    return render_template('index.html')


def register(app):
    app.add_url_rule("/health", endpoint="health", view_func=health)
    app.add_url_rule("/dashboard", endpoint="dashboard", view_func=dashboard)
    app.add_url_rule("/settings", endpoint="settings", view_func=settings)
    app.add_url_rule("/", endpoint="list_projects", view_func=list_projects)
