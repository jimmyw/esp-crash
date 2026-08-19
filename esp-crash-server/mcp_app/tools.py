"""esp-crash MCP tool logic.

Plain functions that take an explicit ``github_user`` and run ACL-scoped ORM
queries, so they're unit-testable without the OAuth/transport layer. Each
mirrors the equivalent app/routes/* query but scopes to the caller's projects
via project_auth membership - the same model the web app enforces under
AUTH_TYPE=github. Every function requires a github_user; there is no unscoped
path.

All functions must be called inside a Flask app context (they use
``app.models.db``'s session) - the @mcp.tool wrappers in mcp_app/__init__.py
provide one.
"""
import datetime

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.models import Crash, CrashTag, Device, ElfFile, ProjectAuth, Tag, db
from app.tags import find_or_create_tag


def _projects_of(github_user):
    """Subquery of project names the user is granted (for IN-scoping mutations
    and cross-table reads) - the ORM equivalent of auth_project_in_filter."""
    return select(ProjectAuth.project_name).where(ProjectAuth.github == github_user)


def _tags_by_crash(crash_ids):
    """Batched fetch of {crash_id: [tag dicts]} for the given crash_ids -
    avoids one query per crash (same idiom as the `builds` attachment in
    get_crash below)."""
    if not crash_ids:
        return {}
    rows = db.session.execute(
        select(CrashTag.crash_id, Tag.tag_id, Tag.name, Tag.description)
        .join(Tag, CrashTag.tag_id == Tag.tag_id)
        .where(CrashTag.crash_id.in_(crash_ids))
    ).mappings().all()
    out = {}
    for r in rows:
        out.setdefault(r["crash_id"], []).append(
            {"tag_id": r["tag_id"], "name": r["name"], "description": r["description"]}
        )
    return out


def _serialize(row):
    """RowMapping -> JSON-friendly dict (datetimes to ISO strings). We never
    select the BYTEA blob columns, so there's nothing binary to drop."""
    out = {}
    for key, value in dict(row).items():
        if isinstance(value, datetime.datetime):
            out[key] = value.isoformat()
        else:
            out[key] = value
    return out


# ---- reads -----------------------------------------------------------------

def list_projects(github_user):
    """Projects the caller can access, with crash counts."""
    crash_count = (
        select(func.count(Crash.crash_id))
        .where(Crash.project_name == ProjectAuth.project_name)
        .scalar_subquery()
        .label("crash_count")
    )
    rows = db.session.execute(
        select(ProjectAuth.project_name, crash_count)
        .where(ProjectAuth.github == github_user)
        .order_by(ProjectAuth.project_name.asc())
    ).mappings().all()
    return [_serialize(r) for r in rows]


def list_crashes(github_user, project_name=None, search=None, tag_id=None, signature=None, limit=50, offset=0):
    """Crashes across the caller's projects, newest first. Optional project
    filter, full-text search (matches the web crash list's textsearch),
    tag_id filter (see list_tags for a project's available tag_ids), and
    signature filter - a non-AI duplicate-grouping fingerprint (see
    app/crash_signature.py); pass another crash's `signature` field to find
    ones with the same likely root cause, the same thing the web UI's
    "Related" link does."""
    conditions = [ProjectAuth.github == github_user]
    if project_name:
        conditions.append(Crash.project_name == project_name)
    if search:
        conditions.append(Crash.textsearch.op("@@")(func.plainto_tsquery(search)))
    if tag_id:
        conditions.append(Crash.crash_id.in_(select(CrashTag.crash_id).where(CrashTag.tag_id == tag_id)))
    if signature:
        conditions.append(Crash.signature == signature)
    rows = db.session.execute(
        select(
            Crash.crash_id, Crash.date, Crash.project_name, Crash.project_ver,
            Crash.device_id, Crash.module_names, Crash.ai_summary, Crash.signature,
            Device.ext_device_id, Device.alias,
        )
        .select_from(Crash)
        .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
        .outerjoin(Device, Crash.device_id == Device.device_id)
        .where(*conditions)
        .order_by(Crash.date.desc(), Crash.crash_id)
        .limit(int(limit))
        .offset(int(offset))
    ).mappings().all()
    tags_by_crash = _tags_by_crash([r["crash_id"] for r in rows])
    results = [_serialize(r) for r in rows]
    for r in results:
        r["tags"] = tags_by_crash.get(r["crash_id"], [])
    return results


def get_crash(github_user, crash_id):
    """Full crash detail incl. the stored symbolicated dump (computed at cron
    time) and the ELF builds available for its project/version. None if the
    crash doesn't exist or the caller lacks access."""
    row = db.session.execute(
        select(
            Crash.crash_id, Crash.date, Crash.project_name, Crash.project_ver,
            Crash.device_id, Device.ext_device_id, Device.alias,
            Crash.dump, Crash.module_map, Crash.module_names, Crash.ai_summary,
            Crash.signature,
        )
        .select_from(Crash)
        .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
        .join(Device, Crash.device_id == Device.device_id)
        .where(Crash.crash_id == crash_id, ProjectAuth.github == github_user)
    ).mappings().first()
    if row is None:
        return None
    builds = db.session.execute(
        select(
            ElfFile.elf_file_id, ElfFile.date, ElfFile.project_ver,
            ElfFile.project_alias, ElfFile.file_size,
        )
        .where(ElfFile.project_name == row["project_name"], ElfFile.project_ver == row["project_ver"])
        .order_by(ElfFile.date.desc())
    ).mappings().all()
    result = _serialize(row)
    result["builds"] = [_serialize(b) for b in builds]
    result["tags"] = _tags_by_crash([crash_id]).get(crash_id, [])
    return result


def list_builds(github_user, project_name):
    """Uploaded ELF builds for a project the caller can access, with crash
    counts, newest first."""
    crash_count = (
        select(func.count())
        .where(Crash.project_name == ElfFile.project_name, Crash.project_ver == ElfFile.project_ver)
        .scalar_subquery()
    )
    rows = db.session.execute(
        select(
            ElfFile.elf_file_id, ElfFile.date, ElfFile.project_name,
            ElfFile.project_ver, ElfFile.project_alias, ElfFile.file_size,
            func.coalesce(crash_count, 0).label("crash_count"),
        )
        .select_from(ElfFile)
        .join(ProjectAuth, ElfFile.project_name == ProjectAuth.project_name)
        .where(ElfFile.project_name == project_name, ProjectAuth.github == github_user)
        .order_by(ElfFile.date.desc())
    ).mappings().all()
    return [_serialize(r) for r in rows]


def get_build(github_user, build_id):
    """Build detail, scoped to the caller's projects. None if missing/forbidden."""
    row = db.session.execute(
        select(
            ElfFile.elf_file_id, ElfFile.date, ElfFile.project_name,
            ElfFile.project_ver, ElfFile.project_alias, ElfFile.file_size,
        )
        .select_from(ElfFile)
        .join(ProjectAuth, ElfFile.project_name == ProjectAuth.project_name)
        .where(ElfFile.elf_file_id == build_id, ProjectAuth.github == github_user)
    ).mappings().first()
    return _serialize(row) if row is not None else None


def list_tags(github_user, project_name):
    """Tags defined for a project the caller can access, for picking an
    existing one before calling add_tag_to_crash."""
    rows = db.session.execute(
        select(Tag.tag_id, Tag.name, Tag.description)
        .join(ProjectAuth, Tag.project_name == ProjectAuth.project_name)
        .where(Tag.project_name == project_name, ProjectAuth.github == github_user)
        .order_by(Tag.name)
    ).mappings().all()
    return [_serialize(r) for r in rows]


# ---- actions ---------------------------------------------------------------

def refresh_crash(github_user, crash_id):
    """Clear a crash's cached dump so the cron worker re-symbolicates it.
    No-op (matched=False) if the caller can't access that crash."""
    res = db.session.execute(
        update(Crash)
        .where(Crash.crash_id == crash_id, Crash.project_name.in_(_projects_of(github_user)))
        .values(dump=None)
    )
    db.session.commit()
    return {"crash_id": crash_id, "refreshed": res.rowcount > 0}


def delete_crash(github_user, crash_id):
    """Delete a crash the caller can access. deleted=0 if not found/forbidden."""
    res = db.session.execute(
        delete(Crash).where(Crash.crash_id == crash_id, Crash.project_name.in_(_projects_of(github_user)))
    )
    db.session.commit()
    return {"crash_id": crash_id, "deleted": res.rowcount}


def delete_build(github_user, build_id):
    """Delete an uploaded ELF build the caller can access."""
    res = db.session.execute(
        delete(ElfFile).where(ElfFile.elf_file_id == build_id, ElfFile.project_name.in_(_projects_of(github_user)))
    )
    db.session.commit()
    return {"build_id": build_id, "deleted": res.rowcount}


def set_build_alias(github_user, build_id, alias):
    """Set the alias for an uploaded ELF build the caller can access.
    updated=False if not found/forbidden."""
    res = db.session.execute(
        update(ElfFile)
        .where(ElfFile.elf_file_id == build_id, ElfFile.project_name.in_(_projects_of(github_user)))
        .values(project_alias=alias)
    )
    db.session.commit()
    return {"build_id": build_id, "updated": res.rowcount > 0, "alias": alias}


def set_device_alias(github_user, device_id, alias):
    """Set the user-defined alias for a device the caller can access (i.e. it
    has appeared in a crash under one of the caller's projects). updated=False
    if not found/forbidden."""
    res = db.session.execute(
        update(Device)
        .where(
            Device.device_id == device_id,
            Device.device_id.in_(select(Crash.device_id).where(Crash.project_name.in_(_projects_of(github_user)))),
        )
        .values(alias=alias)
    )
    db.session.commit()
    return {"device_id": device_id, "updated": res.rowcount > 0, "alias": alias}


def create_project(github_user, project_name):
    """Register a new project owned by the caller. created=False if the caller
    already has a project by that name."""
    if not project_name:
        return {"created": False, "reason": "missing project_name"}
    exists = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, ProjectAuth.github == github_user)
    ).first()
    if exists:
        return {"created": False, "reason": "already exists"}
    db.session.execute(
        insert(ProjectAuth).values(date=func.now(), project_name=project_name, github=github_user)
    )
    db.session.commit()
    return {"created": True, "project_name": project_name}


def add_tag_to_crash(github_user, crash_id, tag_name, tag_description=None):
    """Attach a tag to a crash the caller can access, creating the tag for
    that project if tag_name isn't already one of its tags (case-folded)."""
    crash_project = db.session.execute(
        select(Crash.project_name).where(
            Crash.crash_id == crash_id, Crash.project_name.in_(_projects_of(github_user))
        )
    ).scalar_one_or_none()
    if crash_project is None:
        return {"crash_id": crash_id, "added": False, "reason": "not found or forbidden"}

    tag_id = find_or_create_tag(crash_project, tag_name, tag_description)
    db.session.execute(
        pg_insert(CrashTag).values(crash_id=crash_id, tag_id=tag_id)
        .on_conflict_do_nothing(index_elements=["crash_id", "tag_id"])
    )
    db.session.commit()
    tag_row = db.session.execute(
        select(Tag.tag_id, Tag.name, Tag.description).where(Tag.tag_id == tag_id)
    ).mappings().first()
    return {"crash_id": crash_id, "added": True, "tag": _serialize(tag_row)}


def remove_tag_from_crash(github_user, crash_id, tag_id):
    """Detach a tag from a crash the caller can access (the tag itself is
    left intact for reuse). removed=False if not found/forbidden."""
    res = db.session.execute(
        delete(CrashTag).where(
            CrashTag.crash_id == crash_id,
            CrashTag.tag_id == tag_id,
            CrashTag.crash_id.in_(select(Crash.crash_id).where(Crash.project_name.in_(_projects_of(github_user)))),
        )
    )
    db.session.commit()
    return {"crash_id": crash_id, "tag_id": tag_id, "removed": res.rowcount > 0}
