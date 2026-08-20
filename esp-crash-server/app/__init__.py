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
single-module server.py. (The JSON API under app/api/ is a Blueprint -
nothing calls bare url_for() on those endpoint names, so this concern
doesn't apply there.)

The app is an APIFlask (a thin Flask subclass) rather than plain Flask
purely so app/api/* can use @app.input/@app.output for request validation
and OpenAPI generation - every HTML route below behaves identically either
way. json_errors=False keeps APIFlask's automatic JSON-ification of
raised/aborted HTTP errors scoped to the API surface (see
app/api/errors.py's docstring for why that's safe): plain flask.abort()
and Flask's own 404/405 pages on these HTML routes are unaffected.
"""
import logging
import os

from apiflask import APIFlask
from flask_dance.contrib.github import make_github_blueprint
from werkzeug.middleware.proxy_fix import ProxyFix

from device_url import resolve_device_url

from . import config as config_module
from .rendering import format_datetime, handle_chunking, tag_color

# templates/ lives next to server.py, one level up from this package - Flask
# would otherwise default to looking for app/templates/ since __name__ here
# is "app", not "server".
_TEMPLATE_FOLDER = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates")


def create_app():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    app = APIFlask(
        __name__,
        template_folder=_TEMPLATE_FOLDER,
        title="ESP Crash API",
        docs_path="/api/v1/docs",
        spec_path="/api/v1/openapi.json",
        json_errors=False,
    )
    app.wsgi_app = ProxyFix(
        app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
    )

    config_module.configure_app(app)

    from .models import db
    db.init_app(app)

    app.jinja_env.filters['format_datetime'] = format_datetime
    app.jinja_env.filters['resolve_device_url'] = resolve_device_url
    app.jinja_env.filters['tag_color'] = tag_color

    github_bp = make_github_blueprint()
    app.register_blueprint(github_bp, url_prefix="/login")

    app.before_request(handle_chunking)

    from .routes import core, projects, crashes, builds, devices, slack, ingest, cron, tags

    for module in (core, projects, crashes, builds, devices, slack, ingest, cron, tags):
        module.register(app)

    from .api import register_api
    register_api(app)

    return app
