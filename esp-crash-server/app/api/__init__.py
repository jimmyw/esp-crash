"""JSON REST API for the future React UI - /api/v1/*.

Additive only: no existing HTML route, template, or mcp_app transport code
changes. Every route here is a thin wrapper around mcp_app/tools.py so
this API and the MCP server share one ACL-scoped service layer (see
mcp_app/tools.py's module docstring) - auth is by session cookie
(app/auth.py:api_login_required), not the MCP OAuth bearer flow.

Swagger UI at /api/v1/docs, OpenAPI spec at /api/v1/openapi.json (see
app/__init__.py where the app is constructed as an APIFlask with those
paths configured).
"""
from apiflask import APIBlueprint

api_v1 = APIBlueprint("api_v1", __name__, url_prefix="/api/v1")

from . import csrf as _csrf  # noqa: E402
from . import errors as _errors  # noqa: E402

api_v1.before_request(_csrf.enforce_csrf)
api_v1.after_request(_csrf.apply_cors_headers)

# Import after api_v1 exists - each of these modules attaches routes to it
# via @api_v1.get/.post/etc. at import time.
from . import builds, crashes, devices, projects, settings  # noqa: E402,F401


def register_api(app):
    _errors.register(app)
    app.register_blueprint(api_v1)

    @app.spec_processor
    def _api_only_spec(spec):
        """APIFlask documents every view function on the app by default,
        HTML routes included (they just get a generic response entry). Keep
        the published spec/Swagger UI scoped to the actual JSON API instead
        of mixing in every Jinja-rendered page."""
        spec["paths"] = {
            path: item for path, item in spec["paths"].items() if path.startswith("/api/v1/")
        }
        return spec
