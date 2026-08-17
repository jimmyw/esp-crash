"""Attach/detach tags on a crash's relation. Tag creation is implicit:
adding a tag name that doesn't exist yet for the project creates it (see
app/tags.py). There is no standalone tag-admin/rename/delete-the-tag UI -
only attach/detach, matching what was asked for.

Tags are owned by CrashRelation (project_name, signature) - see
app/models.py - not by the individual crash, so attaching/detaching a tag
here affects every crash that shares this one's signature, not just the
crash being viewed. A crash with no signature has no relation to attach a
tag to."""
from flask import redirect, request, url_for
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..auth import auth_filter, login_required
from ..models import Crash, CrashRelationTag, ProjectAuth, db
from ..tags import find_or_create_tag


def _crash_signature(project_name, crash_id):
    """The crash's signature if it exists and the caller has access,
    else None. Also None (with no way to distinguish) if the crash simply
    has no signature - either way there's no relation to act on."""
    return db.session.execute(
        select(Crash.signature)
        .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
        .where(Crash.crash_id == crash_id, Crash.project_name == project_name, auth_filter(ProjectAuth.github))
    ).scalar_one_or_none()


@login_required
def add_crash_tag(project_name, crash_id):
    """Attach a tag to this crash's relation, creating the tag for this
    project if the submitted name isn't already one of its tags."""
    allowed = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).first()
    if not allowed:
        return "Forbidden: You do not have access to this project.", 403

    signature = _crash_signature(project_name, crash_id)
    if not signature:
        return "This crash has no signature and can't be tagged.", 400

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
        pg_insert(CrashRelationTag).values(project_name=project_name, signature=signature, tag_id=tag_id)
        .on_conflict_do_nothing(index_elements=["project_name", "signature", "tag_id"])
    )
    db.session.commit()
    return redirect(url_for('show_project_crash', project_name=project_name, crash_id=crash_id))


@login_required
def remove_crash_tag(project_name, crash_id, tag_id):
    """Detach a tag from this crash's relation (the tag itself is left
    intact for reuse) - affects every crash sharing this signature."""
    signature = _crash_signature(project_name, crash_id)
    if signature:
        db.session.execute(
            delete(CrashRelationTag).where(
                CrashRelationTag.project_name == project_name,
                CrashRelationTag.signature == signature,
                CrashRelationTag.tag_id == tag_id,
            )
        )
        db.session.commit()
    return redirect(url_for('show_project_crash', project_name=project_name, crash_id=crash_id))


def register(app):
    app.add_url_rule('/projects/<project_name>/<crash_id>/tags', endpoint="add_crash_tag", view_func=add_crash_tag, methods=['POST'])
    app.add_url_rule('/projects/<project_name>/<crash_id>/tags/<int:tag_id>/remove', endpoint="remove_crash_tag", view_func=remove_crash_tag, methods=['POST'])
