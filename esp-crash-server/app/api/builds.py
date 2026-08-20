"""GET /api/v1/projects/<name>/builds, GET/PATCH/DELETE /api/v1/builds/<id>."""
from apiflask import abort
from flask import session

from mcp_app import tools

from ..auth import api_login_required
from . import api_v1
from .schema import not_found_if_none
from .schemas import AliasInSchema, BuildSchema


@api_v1.get("/projects/<project_name>/builds")
@api_v1.output(BuildSchema(many=True))
@api_login_required
def list_builds(project_name):
    """Uploaded ELF builds for a project, with crash counts, newest
    first."""
    return tools.list_builds(session["gh_user"], project_name)


@api_v1.get("/builds/<int:build_id>")
@api_v1.output(BuildSchema)
@api_login_required
def get_build(build_id):
    """Build detail."""
    return not_found_if_none(tools.get_build(session["gh_user"], build_id), "Build not found")


@api_v1.patch("/builds/<int:build_id>")
@api_v1.input(AliasInSchema)
@api_login_required
def set_build_alias(build_id, json_data):
    """Set (or clear) the alias for an uploaded ELF build."""
    result = tools.set_build_alias(session["gh_user"], build_id, json_data["alias"])
    if not result["updated"]:
        abort(404, message="Build not found")
    return result


@api_v1.delete("/builds/<int:build_id>")
@api_login_required
def delete_build(build_id):
    """Permanently delete an uploaded ELF build."""
    result = tools.delete_build(session["gh_user"], build_id)
    if not result["deleted"]:
        abort(404, message="Build not found")
    return result
