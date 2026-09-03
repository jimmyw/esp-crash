"""GET/POST/DELETE /api/v1/crashes - listing, detail, refresh,
reload-summary, delete, and tag attach/detach."""
from apiflask import abort
from flask import current_app, session
from sqlalchemy import func, select, tuple_

import gdb_tickets
from app.models import Crash, CrashRelationTag, db
from mcp_app import tools

from ..auth import api_login_required
from . import api_v1
from .schema import not_found_if_none, paginated
from .schemas import (
    CrashDetailSchema, CrashListQuerySchema, CrashListSchema, GdbSessionSchema,
    TagAddInSchema,
)


def _count_crashes(github_user, query_data):
    """tools.list_crashes doesn't return a full_count (kept lean for MCP
    callers) - a companion count query, same filter conditions minus
    limit/offset, for this endpoint's pagination envelope."""
    conditions = [Crash.project_name.in_(tools._projects_of(github_user))]
    if query_data.get("project_name"):
        conditions.append(Crash.project_name == query_data["project_name"])
    if query_data.get("search"):
        conditions.append(Crash.textsearch.op("@@")(func.plainto_tsquery(query_data["search"])))
    if query_data.get("tag_id"):
        conditions.append(
            tuple_(Crash.project_name, Crash.signature).in_(
                select(CrashRelationTag.project_name, CrashRelationTag.signature)
                .where(CrashRelationTag.tag_id == query_data["tag_id"])
            )
        )
    if query_data.get("signature"):
        conditions.append(Crash.signature == query_data["signature"])
    return db.session.execute(select(func.count()).select_from(Crash).where(*conditions)).scalar_one()


@api_v1.get("/crashes")
@api_v1.input(CrashListQuerySchema, location="query")
@api_v1.output(CrashListSchema)
@api_login_required
def list_crashes(query_data):
    """Crashes across the caller's projects, newest first. Replaces both
    the /projects/<name> and /crash HTML pages - pass project_name to
    filter to one project, tag_id/signature to filter further."""
    github_user = session["gh_user"]
    items = tools.list_crashes(github_user, **query_data)
    full_count = _count_crashes(github_user, query_data)
    return paginated(items, query_data["limit"], query_data["offset"], full_count)


@api_v1.get("/crashes/<int:crash_id>")
@api_v1.output(CrashDetailSchema)
@api_login_required
def get_crash(crash_id):
    """Full crash detail incl. the symbolicated dump and the ELF builds
    available for its project/version."""
    return not_found_if_none(tools.get_crash(session["gh_user"], crash_id), "Crash not found")


@api_v1.post("/crashes/<int:crash_id>/refresh")
@api_login_required
def refresh_crash(crash_id):
    """Clear a crash's cached dump so the cron worker re-symbolicates it."""
    result = tools.refresh_crash(session["gh_user"], crash_id)
    if not result["refreshed"]:
        abort(404, message="Crash not found")
    return result


@api_v1.post("/crashes/<int:crash_id>/reload-summary")
@api_login_required
def reload_crash_summary(crash_id):
    """Clear the AI title/summary on this crash's (project_name,
    signature) relation, so cron regenerates them - affects every crash
    sharing that signature, not just crash_id (see the response's
    project_name/signature fields)."""
    result = tools.reload_crash_summary(session["gh_user"], crash_id)
    if not result["reloaded"]:
        abort(404, message="Crash not found, has no signature, or not accessible")
    return result


@api_v1.delete("/crashes/<int:crash_id>")
@api_login_required
def delete_crash(crash_id):
    """Permanently delete a crash."""
    result = tools.delete_crash(session["gh_user"], crash_id)
    if not result["deleted"]:
        abort(404, message="Crash not found")
    return result


@api_v1.post("/crashes/<int:crash_id>/tags")
@api_v1.input(TagAddInSchema)
@api_login_required
def add_crash_tag(crash_id, json_data):
    """Attach a tag to a crash, creating it for that project if the name
    isn't already one of its tags. Tags belong to the crash's
    (project_name, signature) relation, not crash_id - this affects every
    crash sharing that signature (see the response's project_name/signature
    fields)."""
    result = tools.add_tag_to_crash(
        session["gh_user"], crash_id, json_data["tag_name"], json_data.get("tag_description")
    )
    if not result["added"]:
        status = 400 if result.get("reason") == "crash has no signature" else 404
        abort(status, message=result.get("reason", "could not add tag"))
    return result, 201


@api_v1.delete("/crashes/<int:crash_id>/tags/<int:tag_id>")
@api_login_required
def remove_crash_tag(crash_id, tag_id):
    """Detach a tag from a crash's relation (affects every crash sharing
    the signature; the tag itself is left intact for reuse)."""
    result = tools.remove_tag_from_crash(session["gh_user"], crash_id, tag_id)
    if not result["removed"]:
        abort(404, message="Tag not attached, crash not found, or not accessible")
    return result


@api_v1.post("/crashes/<int:crash_id>/gdb-session")
@api_v1.output(GdbSessionSchema)
@api_login_required
def create_gdb_session(crash_id):
    """Authorise one interactive debug session and say where to connect.

    The ACL check happens here, in the app that already owns the GitHub
    session, and the result is a signed 60-second single-use ticket the browser
    puts in the WebSocket URL (a browser cannot set headers on a WebSocket
    handshake, so a query-string ticket is the available mechanism). The debug
    service re-checks access against the database before starting anything, so
    this ticket is a statement of provenance rather than a bearer credential
    for the crash itself - see gdb_tickets.py.
    """
    secret = current_app.config["GDB_TICKET_SECRET"]
    ws_url = current_app.config["GDB_PUBLIC_WS_URL"]
    if not secret or not ws_url:
        abort(503, message="Interactive debugging is not configured on this server")

    github_user = session["gh_user"]
    crash = not_found_if_none(tools.get_crash(github_user, crash_id), "Crash not found")

    signer = gdb_tickets.TicketSigner(secret)
    ticket = signer.issue(github_user, crash_id)
    separator = "&" if "?" in ws_url else "?"
    return {
        "ws_url": f"{ws_url}{separator}ticket={ticket}",
        "expires_in": signer.ttl_seconds,
        # Echoed back so the terminal can show which toolchain it is talking to;
        # None means the project has none configured and the session will be
        # refused with an explanation.
        "toolchain": crash.get("toolchain"),
    }
