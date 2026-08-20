"""GET/POST /api/v1/projects, plus project-scoped relations and tags."""
from apiflask import abort
from flask import session

from mcp_app import tools

from ..auth import api_login_required
from . import api_v1
from .schemas import (
    PaginationQuerySchema, ProjectCreateInSchema, ProjectSchema,
    RelationListSchema, TagSchema,
)


@api_v1.get("/projects")
@api_v1.output(ProjectSchema(many=True))
@api_login_required
def list_projects():
    """Projects the caller can access, with crash counts."""
    return tools.list_projects(session["gh_user"])


@api_v1.post("/projects")
@api_v1.input(ProjectCreateInSchema)
@api_login_required
def create_project(json_data):
    """Register a new project owned by the caller."""
    result = tools.create_project(session["gh_user"], json_data["project_name"])
    if not result["created"]:
        status = 409 if result.get("reason") == "already exists" else 400
        abort(status, message=result.get("reason", "could not create project"))
    return result, 201


@api_v1.get("/projects/<project_name>/relations")
@api_v1.input(PaginationQuerySchema, location="query")
@api_v1.output(RelationListSchema)
@api_login_required
def list_relations(project_name, query_data):
    """Grouped/deduplicated crash view - one row per stack signature,
    a companion to GET /crashes for spotting the same bug across crashes."""
    return tools.list_relations(session["gh_user"], project_name, **query_data)


@api_v1.get("/projects/<project_name>/tags")
@api_v1.output(TagSchema(many=True))
@api_login_required
def list_tags(project_name):
    """Tags defined for a project, for picking an existing one before
    calling POST /crashes/<id>/tags."""
    return tools.list_tags(session["gh_user"], project_name)
