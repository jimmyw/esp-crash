"""Automated crash summary + tagging via Claude's remote MCP connector.

Calls the Anthropic Messages API with the app's own MCP server declared as a
remote tool source (`mcp_servers` + an `mcp_toolset` tool) - Claude fetches
crash context and applies tags itself, server-side, inside one API call, via
the service-token identity in mcp_app/auth.py. Kept out of cron.py so
`app.ai_tagging.summarize_and_tag` is a single, stable mock target for tests,
matching how app.decode is split out for cron's symbolication step.
"""
from anthropic import Anthropic
from flask import current_app
from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .models import Crash, CrashTag, db

MCP_BETA = "mcp-client-2025-11-20"
# Haiku 4.5 over Sonnet 5: this runs on every new crash, and in practice
# most crashes within a project cluster around a handful of recurring root
# causes (e.g. a firmware rollout tripping the same watchdog across many
# devices at once) - reusing an existing tag is the common case, which
# Haiku handles fine. Revisit if summary/tagging quality regresses.
MODEL = "claude-haiku-4-5"


def _find_duplicate(project_name, dump, crash_id):
    """Most recent other already-summarized crash in the same project whose
    symbolicated output is byte-identical to this one's, if any. Matches on
    Crash.dump (what the AI actually reads and what's shown on the crash
    page) rather than the raw crash_dmp blob - it's the field that
    determines the summary/tags, and it's deterministic for a true repeat
    (e.g. a retried upload, or a device re-crashing in identical state).
    Does NOT catch "same root cause, different device" - device-specific
    state makes the symbolicated dump unique even for the same bug; see
    _find_signature_duplicate for that case."""
    return db.session.execute(
        select(Crash.crash_id, Crash.ai_summary)
        .where(
            Crash.project_name == project_name,
            Crash.dump == dump,
            Crash.ai_summary.is_not(None),
            Crash.crash_id != crash_id,
        )
        .order_by(Crash.date.desc())
        .limit(1)
    ).mappings().first()


def _find_signature_duplicate(project_name, signature, crash_id):
    """Most recent other already-summarized crash in the same project with
    the same non-AI crash_signature.py fingerprint - catches "same root
    cause, different device" duplicates that _find_duplicate's exact-dump
    match misses (e.g. a watchdog firing on the same task across many
    devices, where only pointer/register values differ)."""
    return db.session.execute(
        select(Crash.crash_id, Crash.ai_summary)
        .where(
            Crash.project_name == project_name,
            Crash.signature == signature,
            Crash.ai_summary.is_not(None),
            Crash.crash_id != crash_id,
        )
        .order_by(Crash.date.desc())
        .limit(1)
    ).mappings().first()


def _copy_tags(source_crash_id, target_crash_id):
    tag_ids = db.session.execute(
        select(CrashTag.tag_id).where(CrashTag.crash_id == source_crash_id)
    ).scalars().all()
    for tag_id in tag_ids:
        db.session.execute(
            pg_insert(CrashTag).values(crash_id=target_crash_id, tag_id=tag_id)
            .on_conflict_do_nothing(index_elements=["crash_id", "tag_id"])
        )


def summarize_and_tag(crash_id, project_name):
    """Ask Claude to summarize this crash and apply appropriate tags via the
    app's own MCP server, then store the summary. Raises on any failure -
    callers should catch, log, and move on: ai_summary stays NULL, so the
    crash is picked up again on a later cron tick.

    First checks for an exact-content duplicate (see _find_duplicate), then
    a same-signature duplicate (see _find_signature_duplicate) and, if
    either is found, copies its summary and tags directly - no API call at
    all."""
    dump, signature = db.session.execute(
        select(Crash.dump, Crash.signature).where(Crash.crash_id == crash_id)
    ).one_or_none() or (None, None)

    if dump:
        duplicate = _find_duplicate(project_name, dump, crash_id)
        if duplicate is None and signature:
            duplicate = _find_signature_duplicate(project_name, signature, crash_id)
        if duplicate is not None:
            summary = f"(Same as crash #{duplicate['crash_id']}.) {duplicate['ai_summary']}"
            _copy_tags(duplicate["crash_id"], crash_id)
            db.session.execute(
                update(Crash).where(Crash.crash_id == crash_id).values(ai_summary=summary)
            )
            db.session.commit()
            return summary

    client = Anthropic(api_key=current_app.config["ANTHROPIC_API_KEY"])
    mcp_url = current_app.config["MCP_PUBLIC_URL"].rstrip("/") + "/mcp"

    response = client.beta.messages.create(
        model=MODEL,
        max_tokens=4096,
        betas=[MCP_BETA],
        mcp_servers=[{
            "type": "url",
            "name": "esp-crash",
            "url": mcp_url,
            "authorization_token": current_app.config["MCP_SERVICE_TOKEN"],
        }],
        tools=[{"type": "mcp_toolset", "mcp_server_name": "esp-crash"}],
        messages=[{
            "role": "user",
            "content": (
                f"Crash {crash_id} in project '{project_name}' was just symbolicated. "
                "Use the esp-crash MCP tools: call get_crash to read its details, and "
                "list_tags to see this project's existing tags. Write a short (2-3 "
                "sentence) plain-English summary of what the crash is and its likely "
                "cause. Then call add_tag_to_crash once per tag that fits - reuse an "
                "existing tag whenever one applies, and only create a new tag when "
                "nothing existing fits. Do not remove any existing tags. Respond with "
                "only the summary text, nothing else."
            ),
        }],
    )

    summary = "".join(
        block.text for block in response.content if block.type == "text"
    ).strip()

    db.session.execute(
        update(Crash).where(Crash.crash_id == crash_id).values(ai_summary=summary)
    )
    db.session.commit()
    return summary
