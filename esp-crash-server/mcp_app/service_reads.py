"""Unscoped reads for the batch decode path.

Everything in `mcp_app/tools.py` takes an explicit `github_user` and scopes to
that user's projects; its docstring promises "there is no unscoped path". The
cron decode genuinely needs one - it processes every project - so rather than
weaken that promise, the exception lives here, alone, in a file whose entire
purpose is to be the one place a reviewer has to audit.

This is a real privilege. Whoever can call the endpoint that uses this can read
any crash's dump and any project's build ELF. It is gated on a dedicated bearer
token, reachable only on the compose-internal network, and the route is not
registered at all when that token is unset. Deliberately *not* the MCP service
identity: making `esp-crash-bot` work for cron would mean granting it a
`project_auth` row per project, which would silently opt every project into the
AI summarize/tag step that cron gates on an explicit grant, and would hand
anyone holding that token `delete_crash` and `delete_build` across all projects.

Kept as narrow as possible on purpose: one function, by primary key. No listing,
no search, no enumeration helper - so a leaked token cannot be used to discover
what exists, only to fetch a crash whose id is already known.
"""
from sqlalchemy import func, select

from app.models import Crash, ElfFile, ProjectSettings, db


def get_decode_artifacts(crash_id, elf_file_id=None):
    """The bytes and settings the batch decode needs for one crash.

    Mirrors `mcp_app.tools.get_debug_artifacts` minus the ProjectAuth join.
    Returns None when the crash does not exist.

    `elf_file_id` picks a specific build; by default the newest matching the
    crash's version is used. `elf_count` is reported so the caller can say which
    build a report was produced against when a version has more than one - the
    old batch path looped over every build and concatenated a report per build,
    which left `module_map` describing the *oldest* while the signature came
    from the newest.
    """
    row = db.session.execute(
        select(
            Crash.crash_id, Crash.project_name, Crash.project_ver,
            Crash.crash_dmp, ProjectSettings.toolchain,
        )
        .select_from(Crash)
        .outerjoin(ProjectSettings, ProjectSettings.project_name == Crash.project_name)
        .where(Crash.crash_id == crash_id)
    ).mappings().first()
    if row is None:
        return None

    matching = (ElfFile.project_name == row["project_name"],
                ElfFile.project_ver == row["project_ver"])
    elf_count = db.session.execute(
        select(func.count(ElfFile.elf_file_id)).where(*matching)
    ).scalar_one()

    query = select(ElfFile.elf_file_id, ElfFile.date, ElfFile.elf_file).where(*matching)
    if elf_file_id is not None:
        query = query.where(ElfFile.elf_file_id == elf_file_id)
    elf = db.session.execute(
        query.order_by(ElfFile.date.desc()).limit(1)
    ).mappings().first()

    return {
        "crash_id": row["crash_id"],
        "project_name": row["project_name"],
        "project_ver": row["project_ver"],
        "toolchain": row["toolchain"],
        "dump": bytes(row["crash_dmp"]) if row["crash_dmp"] is not None else None,
        "elf_file_id": elf["elf_file_id"] if elf else None,
        "elf_date": elf["date"].isoformat() if elf and elf["date"] else None,
        "elf_count": elf_count,
        "prog": bytes(elf["elf_file"]) if elf and elf["elf_file"] is not None else None,
    }
