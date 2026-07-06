"""esp-crash-server Flask app package.

Split out of the original monolithic server.py: app factory here, shared
DB/auth/rendering helpers as modules, routes grouped by resource under
app/routes/. This is a mechanical reorganization only - SQL and route logic
are unchanged from the original file.

Routes are registered directly on the Flask app object (app.add_url_rule),
not via Flask Blueprint objects: Blueprint.add_url_rule always prefixes
registered endpoint names with the blueprint's name (e.g.
"crashes.show_project_crash"), which would break every url_for() call in
the existing templates - they all use bare endpoint names
(url_for('show_project_crash', ...)) inherited from the original
single-module server.py.
"""
import logging
import os

from flask import Flask
from flask_dance.contrib.github import make_github_blueprint
from werkzeug.middleware.proxy_fix import ProxyFix

from device_url import resolve_device_url

from . import config as config_module
from .rendering import format_datetime, handle_chunking

# templates/ lives next to server.py, one level up from this package - Flask
# would otherwise default to looking for app/templates/ since __name__ here
# is "app", not "server".
_TEMPLATE_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


def create_app():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    app = Flask(__name__, template_folder=_TEMPLATE_FOLDER)
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )

    config_module.configure_app(app)

    from .models import db
    db.init_app(app)

    app.jinja_env.filters['format_datetime'] = format_datetime
    app.jinja_env.filters['resolve_device_url'] = resolve_device_url

    github_bp = make_github_blueprint()
    app.register_blueprint(github_bp, url_prefix="/login")

    app.before_request(handle_chunking)

    from .routes import core, projects, crashes, builds, devices, slack, ingest, cron

    for module in (core, projects, crashes, builds, devices, slack, ingest, cron):
        module.register(app)

    return app
