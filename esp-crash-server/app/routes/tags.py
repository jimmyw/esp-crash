"""Attach/detach tags on a crash. Tag creation is implicit: adding a tag
name that doesn't exist yet for the project creates it (see app/tags.py).
There is no standalone tag-admin/rename/delete-the-tag UI - only
attach/detach from a crash, matching what was asked for."""
from flask import redirect, request, url_for
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..auth import auth_filter, login_required
from ..models import Crash, CrashTag, ProjectAuth, db
from ..tags import find_or_create_tag


@login_required
def add_crash_tag(project_name, crash_id):
    """Attach a tag to a crash, creating the tag for this project if the
    submitted name isn't already one of its tags."""
    allowed = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).first()
    if not allowed:
        return "Forbidden: You do not have access to this project.", 403

    # A typed new-tag name takes priority over whatever's selected in the
    # existing-tags dropdown, so picking a tag then also typing a new one
    # does what it looks like it does. '__new_tag__' is the "+ New tag..."
    # option's value (a UI sentinel that reveals the name/description
    # fields client-side) - it must never be used as an actual tag name if
    # submitted without new_tag_name filled in.
    selected_tag = (request.form.get('tag_name') or '').strip()
    if selected_tag == '__new_tag__':
        selected_tag = ''
    tag_name = (request.form.get('new_tag_name') or selected_tag or '').strip()
    if not tag_name:
        return "Missing tag_name", 400
    tag_description = (request.form.get('tag_description') or '').strip() or None

    tag_id = find_or_create_tag(project_name, tag_name, tag_description)
    db.session.execute(
        pg_insert(CrashTag).values(crash_id=crash_id, tag_id=tag_id)
        .on_conflict_do_nothing(index_elements=["crash_id", "tag_id"])
    )
    db.session.commit()
    return redirect(url_for('show_project_crash', project_name=project_name, crash_id=crash_id))


@login_required
def remove_crash_tag(project_name, crash_id, tag_id):
    """Detach a tag from a crash (the tag itself is left intact for reuse)."""
    db.session.execute(
        delete(CrashTag).where(
            CrashTag.crash_id == crash_id,
            CrashTag.tag_id == tag_id,
            CrashTag.crash_id.in_(
                select(Crash.crash_id)
                .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
                .where(Crash.project_name == project_name, auth_filter(ProjectAuth.github))
            ),
        )
    )
    db.session.commit()
    return redirect(url_for('show_project_crash', project_name=project_name, crash_id=crash_id))


def register(app):
    app.add_url_rule('/projects/<project_name>/<crash_id>/tags', endpoint="add_crash_tag", view_func=add_crash_tag, methods=['POST'])
    app.add_url_rule('/projects/<project_name>/<crash_id>/tags/<int:tag_id>/remove', endpoint="remove_crash_tag", view_func=remove_crash_tag, methods=['POST'])
