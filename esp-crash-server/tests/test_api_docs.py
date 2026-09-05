"""What the published OpenAPI spec covers, and whether it still tells the
truth about the ingestion endpoints.

Those three are documented by hand (see app/api/ingest_spec.py) because
decorating them would change what a device gets back. Hand-written docs drift,
so these tests check them against the code rather than trusting them.
"""
import ast
import os

import pytest

from app.api import ingest_spec

_INGEST_SOURCE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "app", "routes", "ingest.py",
)

# Documented path -> the view function that serves it.
_PATH_TO_VIEW = {
    "/dump": "dump",
    "/upload_elf": "upload_elf",
    "/upload_module_elf": "upload_module_elf",
}


@pytest.fixture
def spec(app):
    with app.test_request_context():
        return app._get_spec(force_update=True)


def _returned_status_codes(view_name):
    """Every status code the view actually returns, read from its source.

    `return "...", 400` and `return f"...", 200` both parse to a Tuple whose
    second element is a constant int.
    """
    tree = ast.parse(open(_INGEST_SOURCE).read())
    func = next(n for n in tree.body
                if isinstance(n, ast.FunctionDef) and n.name == view_name)
    codes = set()
    for node in ast.walk(func):
        if isinstance(node, ast.Return) and isinstance(node.value, ast.Tuple):
            last = node.value.elts[-1]
            if isinstance(last, ast.Constant) and isinstance(last.value, int):
                codes.add(last.value)
    return codes


def test_html_pages_are_not_published(spec):
    """The reason the spec is filtered at all: without it ~40 Jinja pages and
    OAuth callbacks show up with empty JSON schemas."""
    for page in ("/dashboard", "/settings", "/slack/callback", "/cron"):
        assert page not in spec["paths"]


def test_ingestion_endpoints_are_published(spec):
    """They sit outside /api/v1, so the prefix filter used to drop them - and
    they are the endpoints devices and CI actually call."""
    for path in _PATH_TO_VIEW:
        assert path in spec["paths"], f"{path} missing from the published spec"
        assert "post" in spec["paths"][path]


def test_every_documented_path_is_actually_routed(app):
    """A documented endpoint that does not exist is worse than an undocumented
    one."""
    routed = {(rule.rule, method)
              for rule in app.url_map.iter_rules()
              for method in rule.methods}
    for path, item in ingest_spec.INGEST_PATHS.items():
        for method in item:
            assert (path, method.upper()) in routed, \
                f"{method.upper()} {path} is documented but not registered"


@pytest.mark.parametrize("path,view", sorted(_PATH_TO_VIEW.items()))
def test_documented_status_codes_match_the_view(path, view):
    """The drift guard that matters: add a 413 to an upload and forget the
    docs, and this fails instead of the docs quietly going stale."""
    documented = {int(c) for c in ingest_spec.INGEST_PATHS[path]["post"]["responses"]}
    assert documented == _returned_status_codes(view), (
        f"{path} documents {sorted(documented)} but the view returns "
        f"{sorted(_returned_status_codes(view))}"
    )


def test_ingestion_endpoints_are_documented_as_unauthenticated(spec):
    """They are deliberately open - firmware cannot do an OAuth flow - and the
    docs must not imply otherwise."""
    for path in _PATH_TO_VIEW:
        assert spec["paths"][path]["post"]["security"] == []


def test_ingestion_responses_are_documented_as_text_not_json(spec):
    """APIFlask's own inference claims application/json for these; they only
    ever return plain text."""
    for path in _PATH_TO_VIEW:
        for response in spec["paths"][path]["post"]["responses"].values():
            assert set(response["content"]) == {"text/plain"}
