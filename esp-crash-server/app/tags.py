"""Shared tag find-or-create logic used by both the web routes
(app/routes/tags.py) and the MCP tools (mcp_app/tools.py), so the
case-folding + upsert dance lives in exactly one place."""
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .models import Tag, db


def normalize_tag_name(name):
    return (name or "").strip().lower()


def find_or_create_tag(project_name, name, description=None):
    """Returns the tag_id for (project_name, name), case-folded. Reuses an
    existing tag if present - the supplied description is ignored in that
    case, since an existing tag's description isn't editable via this path."""
    name = normalize_tag_name(name)
    stmt = pg_insert(Tag).values(
        project_name=project_name, name=name, description=description
    ).on_conflict_do_nothing(index_elements=["project_name", "name"])
    db.session.execute(stmt)
    return db.session.execute(
        select(Tag.tag_id).where(Tag.project_name == project_name, Tag.name == name)
    ).scalar_one()
