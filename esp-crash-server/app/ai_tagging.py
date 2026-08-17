"""Automated crash summary + tagging via Claude's remote MCP connector.

Calls the Anthropic Messages API with the app's own MCP server declared as a
remote tool source (`mcp_servers` + an `mcp_toolset` tool) - Claude fetches
crash context and applies tags itself, server-side, inside one API call, via
the service-token identity in mcp_app/auth.py. Kept out of cron.py so
`app.ai_tagging.summarize_and_tag` is a single, stable mock target for tests,
matching how app.decode is split out for cron's symbolication step.
"""
import re

from anthropic import Anthropic
from flask import current_app
from sqlalchemy import func, select, update

from .models import Crash, CrashRelation, db

# Matches the "TITLE: ...\nDESCRIPTION: ..." format the prompt below asks
# the model for. DOTALL so DESCRIPTION can span multiple lines/paragraphs.
_TITLE_DESCRIPTION_RE = re.compile(r'TITLE:\s*(.+?)\s*\n+DESCRIPTION:\s*(.+)', re.DOTALL)

MCP_BETA = "mcp-client-2025-11-20"
# Haiku 4.5 over Sonnet 5: this runs on every new crash, and in practice
# most crashes within a project cluster around a handful of recurring root
# causes (e.g. a firmware rollout tripping the same watchdog across many
# devices at once) - reusing an existing tag is the common case, which
# Haiku handles fine. Revisit if summary/tagging quality regresses.
MODEL = "claude-haiku-4-5"


def summarize_and_tag(crash_id, project_name):
    """Ask Claude to review the group of crashes that share this crash's
    signature and apply appropriate tags via the app's own MCP server, then
    store a short title (ai_title) and a longer description (ai_summary) on
    the owning CrashRelation - see app/models.py. Raises on any failure -
    callers should catch, log, and move on: the relation's ai_summary stays
    NULL, so the group is picked up again on a later cron tick.

    `crash_id` must belong to a crash with a non-NULL signature (cron only
    selects those) - it's used purely as a representative example to show
    the model; the review it produces applies to the whole
    (project_name, signature) group, not just this one occurrence.

    If the relation already has a review (e.g. another crash in the same
    group was processed first, earlier this tick or previously), returns it
    directly with no API call - this replaces what used to be dump/signature
    duplicate-detection against other crash rows: now there's simply one
    owning row per group to check. Returns {"title": ..., "summary": ...}."""
    signature = db.session.execute(
        select(Crash.signature).where(Crash.crash_id == crash_id)
    ).scalar_one_or_none()
    if not signature:
        raise ValueError(f"crash {crash_id} has no signature - can't be reviewed as a group")

    existing = db.session.execute(
        select(CrashRelation.ai_title, CrashRelation.ai_summary)
        .where(CrashRelation.project_name == project_name, CrashRelation.signature == signature)
    ).mappings().first()
    if existing and existing["ai_summary"] is not None:
        return {"title": existing["ai_title"], "summary": existing["ai_summary"]}

    occurrence_count = db.session.execute(
        select(func.count(Crash.crash_id)).where(
            Crash.project_name == project_name, Crash.signature == signature
        )
    ).scalar_one()

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
                f"Crash {crash_id} in project '{project_name}' is one of {occurrence_count} "
                "crashes that share the same stack-fingerprint signature (the same likely "
                "root cause). You're writing a title and description for this whole class "
                "of crash - not just this single occurrence - and any tags you apply cover "
                "every crash in the group. "
                "Use the esp-crash MCP tools: call get_crash on crash "
                f"{crash_id} as a representative example, and list_tags to see this "
                "project's existing tags. Then call add_tag_to_crash once per tag that "
                "fits - reuse an existing tag whenever one applies, and only create a new "
                "tag when nothing existing fits. Do not remove any existing tags. Do not "
                "narrate your steps or explain what you're about to do before or between "
                "tool calls - make all the tool calls first, then send one final message "
                "with nothing but a title and a description, in exactly this format and "
                "nothing else (no preamble, no markdown):\n\n"
                "TITLE: <a short headline, ideally under 60 characters, naming the crash "
                "site and cause, e.g. \"Core dump in mqtt.c assert\">\n"
                "DESCRIPTION: <a short (2-3 sentence) plain-English description of what "
                "this class of crash is and its likely cause>\n\n"
                "Both are shown as-is to a human reading the crash report."
            ),
        }],
    )

    # response.content is the full flattened transcript of the server-side
    # tool-use turns (text, tool_use, tool_result, text, tool_use, ...,
    # text) - only the trailing run of text blocks is the final answer;
    # earlier text blocks are narration Claude produced between tool calls
    # ("I'll start by...", "Now I'll tag this...") and must not end up in
    # the stored summary.
    summary_blocks = []
    for block in reversed(response.content):
        if block.type != "text":
            break
        summary_blocks.append(block.text)
    text = "\n\n".join(reversed(summary_blocks)).strip()

    match = _TITLE_DESCRIPTION_RE.search(text)
    if not match:
        raise ValueError(f"Model response didn't match the TITLE/DESCRIPTION format: {text!r}")
    title, summary = match.group(1).strip(), match.group(2).strip()

    db.session.execute(
        update(CrashRelation)
        .where(CrashRelation.project_name == project_name, CrashRelation.signature == signature)
        .values(ai_title=title, ai_summary=summary)
    )
    db.session.commit()
    return {"title": title, "summary": summary}
