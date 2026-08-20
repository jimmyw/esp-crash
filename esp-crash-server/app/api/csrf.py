"""CSRF defense for the cookie-authenticated /api/v1 surface: a required
custom header (which a forged cross-site <form> POST can't set) plus a
strict CORS origin allow-list (so a credentialed cross-origin fetch() from
an unlisted origin never gets a readable response either). Two independent
layers, no CSRF token/extra session state needed - see the plan doc for
the full rationale.

Runs for every method in AUTH_TYPE=none dev mode too: the threat model is
"the browser holds a valid session cookie", which is true even for the
gh_user="none" sentinel session.
"""
import os

from apiflask import abort
from flask import request

API_CLIENT_HEADER = "X-Api-Client"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _allowed_origins():
    raw = os.environ.get("API_CORS_ORIGINS", "")
    return {origin.strip() for origin in raw.split(",") if origin.strip()}


def enforce_csrf():
    if request.method in _MUTATING_METHODS and request.headers.get(API_CLIENT_HEADER) != "1":
        abort(403, message=f"Missing required {API_CLIENT_HEADER} header")


def apply_cors_headers(response):
    origin = request.headers.get("Origin")
    if origin and origin in _allowed_origins():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
        response.headers["Access-Control-Allow-Headers"] = f"{API_CLIENT_HEADER}, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        response.headers["Vary"] = "Origin"
    return response
