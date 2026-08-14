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
from sqlalchemy import update

from .models import Crash, db

MCP_BETA = "mcp-client-2025-11-20"
# Haiku 4.5 over Sonnet 5: this runs on every new crash, and in practice
# most crashes within a project cluster around a handful of recurring root
# causes (e.g. a firmware rollout tripping the same watchdog across many
# devices at once) - reusing an existing tag is the common case, which
# Haiku handles fine. Revisit if summary/tagging quality regresses.
MODEL = "claude-haiku-4-5"


def summarize_and_tag(crash_id, project_name):
    """Ask Claude to summarize this crash and apply appropriate tags via the
    app's own MCP server, then store the summary. Raises on any failure -
    callers should catch, log, and move on: ai_summary stays NULL, so the
    crash is picked up again on a later cron tick."""
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
