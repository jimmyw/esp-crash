"""Custom JSON error shape for /api/v1: {"error": {"code": ..., "message":
...}} instead of APIFlask's default {"detail": ..., "message": ...}.

Registered via `app.error_processor`, which is an app-wide hook (APIFlask
has no blueprint-scoped equivalent) - but app/__init__.py constructs the
app with `json_errors=False`, so plain flask.abort()/404s/500s on the
existing HTML routes are never routed through this at all. Only
apiflask.abort() calls and @app.input validation failures raise the
HTTPError this processes, and only app/api/* code (plus
app/auth.py:api_login_required) ever raises those - so in practice this
only ever fires for the API surface.
"""
from apiflask import HTTPError

_CODES = {
    400: "bad_request",
    401: "unauthorized",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    422: "validation_error",
    500: "internal_error",
}


def register(app):
    @app.error_processor
    def _json_error(error: HTTPError):
        code = _CODES.get(error.status_code, "error")
        body = {"error": {"code": code, "message": error.message}}
        if error.detail:
            body["error"]["detail"] = error.detail
        return body, error.status_code, error.headers
