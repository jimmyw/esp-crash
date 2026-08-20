"""Small response-shaping helpers shared by the app/api/* route modules -
not to be confused with app/api/schemas.py (the marshmallow Schema
classes used for @app.input/@app.output validation and OpenAPI docs).
"""
from apiflask import abort


def paginated(items, limit, offset, full_count):
    """The `{"items", "limit", "offset", "full_count"}` envelope every list
    endpoint returns - mirrors the window-function pagination pattern
    already used by project.html/builds.html/relations.html."""
    return {"items": items, "limit": limit, "offset": offset, "full_count": full_count}


def not_found_if_none(value, message="Not found"):
    """mcp_app/tools.py returns None for both "doesn't exist" and "caller
    lacks access" - collapsed to 404 here so the API never leaks which one
    it was, matching how the HTML app already behaves for crash/build
    access (see e.g. get_build's docstring)."""
    if value is None:
        abort(404, message=message)
    return value
