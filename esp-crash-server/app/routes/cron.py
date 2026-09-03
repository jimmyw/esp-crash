"""Cron-polled crash processing: symbolication, webhook, and Slack
notification dispatch. Mechanical move from server.py - logic unchanged,
endpoint name preserved exactly (registered directly on the app object, not
via Flask Blueprint - see core.py for why). Deliberately un-authenticated
and polled via HTTP by a sidecar container (see docker-compose.yml `cron`
service) rather than a real cron/celery job - kept as-is for this phase."""
import os
import time

import requests
import slack_sdk
from flask import current_app
from slack_sdk.errors import SlackApiError
from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert

from .. import decode_client
from ..ai_tagging import summarize_and_tag
from ..crash_signature import compute_signature
from ..models import Crash, CrashRelation, ElfFile, ProjectAuth, ProjectSlackIntegration, ProjectWebhook, db
from ..rendering import external_url_for


def _upsert_relation(project_name, signature):
    """Ensure a CrashRelation row exists for (project_name, signature)
    before any crash is given that signature - crash.signature has an FK
    to crash_relation, so the relation must exist first. No-op if
    compute_signature() found no parseable backtrace (signature is None)."""
    if not signature:
        return
    db.session.execute(
        pg_insert(CrashRelation).values(project_name=project_name, signature=signature)
        .on_conflict_do_nothing(index_elements=["project_name", "signature"])
    )


DEFAULT_TICK_BUDGET_SECONDS = 60


def _tick_budget():
    try:
        return int(os.environ.get("DECODE_TICK_BUDGET_SECONDS",
                                  DEFAULT_TICK_BUDGET_SECONDS))
    except ValueError:
        return DEFAULT_TICK_BUDGET_SECONDS


def _decode_one(crash):
    """Decode one crash, returning `(dump_text, module_map)` or None.

    None means "leave the row alone and try again next tick". Anything
    returned is stored, including a permanent failure's message - which is what
    stops an undecodable artifact from being reprocessed forever, and matches
    the old in-process path's habit of storing "# esp-coredump unavailable".
    """
    try:
        result = decode_client.decode_crash(crash["crash_id"])
    except decode_client.DecodeUnavailable as e:
        current_app.logger.warning("  decode deferred: %s", e)
        return None
    except decode_client.DecodePermanent as e:
        current_app.logger.error("  decode failed permanently: %s", e)
        return str(e), []

    decode_client.log_result(crash["crash_id"], result)
    return result["report"], result["modules"]


def cron():
    """Process pending crash dumps and send webhooks."""

    # Metadata only - deliberately *not* crash_dmp. Decoding is now an HTTP
    # call that can take seconds, and holding open the transaction that read a
    # multi-megabyte blob across it would leave a connection idle-in-transaction,
    # blocking VACUUM on the largest tables in this database. Committing right
    # after the read also means cron stops pulling every pending crash's dump
    # out of Postgres just to hand it to something else.
    elf_count = (
        select(func.count(ElfFile.elf_file_id))
        .where(ElfFile.project_name == Crash.project_name, ElfFile.project_ver == Crash.project_ver)
        .scalar_subquery()
    )
    crashes = db.session.execute(
        select(Crash.crash_id, Crash.date, Crash.project_name, Crash.project_ver)
        .where(Crash.dump.is_(None), elf_count > 0)
        .order_by(Crash.crash_id.desc())
        .limit(10)
    ).mappings().all()
    db.session.commit()

    if crashes and not decode_client.configured():
        # There is no in-process decoder any more: this image ships neither a
        # toolchain nor esp-coredump. Say so once per tick rather than logging a
        # per-crash warning, and leave every row untouched.
        current_app.logger.error(
            "DECODE_SERVICE_URL is not set, so %s pending crash(es) cannot be "
            "decoded - decoding now happens in the esp-crash-gdb service",
            len(crashes))
        crashes = []

    if crashes:
        current_app.logger.info("Processing {} crashes".format(len(crashes)))
    processed_anything = bool(crashes)

    # A wall-clock budget, because the signature backfill and the AI review
    # passes run after this loop in the same function: a backlog of slow
    # decodes would otherwise starve them indefinitely.
    deadline = time.monotonic() + _tick_budget()

    for index, crash in enumerate(crashes):
        if time.monotonic() > deadline:
            current_app.logger.info(
                "  decode budget spent; deferring {} crash(es) to the next tick".format(
                    len(crashes) - index))
            break

        current_app.logger.info("Processing crash {} project_name '{}' date '{}'".format(crash["crash_id"], crash["project_name"], crash["date"]))

        outcome = _decode_one(crash)
        if outcome is None:
            # Transient: leave dump NULL so the next tick retries. Storing
            # anything here would mark the crash processed when the real
            # problem was a service outage or a missing configuration.
            continue
        dump, module_map = outcome

        module_names = [m["name"] for m in module_map]
        signature = compute_signature(dump)
        _upsert_relation(crash["project_name"], signature)
        db.session.execute(
            update(Crash)
            .where(Crash.crash_id == crash["crash_id"])
            .values(
                dump=dump, module_names=module_names, module_map=module_map,
                signature=signature,
            )
        )
        db.session.commit()
        current_app.logger.info("Updated crash {} (modules: {})".format(crash["crash_id"], module_names))

        # Send webhooks
        project_name = crash["project_name"]
        webhooks = db.session.execute(
            select(ProjectWebhook.webhook_url).where(ProjectWebhook.project_name == project_name)
        ).mappings().all()

        if webhooks:
            current_app.logger.info(f"Found {len(webhooks)} webhooks for project {project_name}")
            details_url = external_url_for('show_project_crash', project_name=crash["project_name"], crash_id=crash["crash_id"])

            current_app.logger.info(f"Generated details URL for crash {crash['crash_id']}: {details_url}")

            payload = {
                "project_name": crash["project_name"],
                "project_ver": crash["project_ver"],
                "crash_id": crash["crash_id"],
                "crash_dump_snippet": dump[:500],
                "details_url": details_url
            }
            headers = {
                'User-Agent': 'ESP-Crash-Webhook-Notifier/1.0',
                'Content-Type': 'application/json'
            }

            for webhook in webhooks:
                webhook_url = webhook["webhook_url"]
                try:
                    response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
                    response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                    current_app.logger.info(f"Successfully sent webhook to {webhook_url} for crash {crash['crash_id']}")
                except requests.exceptions.RequestException as e:
                    current_app.logger.error(f"Failed to send webhook to {webhook_url} for crash {crash['crash_id']}: {e}")
        else:
            current_app.logger.info(f"No webhooks found for project {project_name}")

        # Send Slack notifications
        slack_integrations = db.session.execute(
            select(
                ProjectSlackIntegration.slack_access_token,
                ProjectSlackIntegration.slack_channel_id,
                ProjectSlackIntegration.slack_channel_name,
            ).where(ProjectSlackIntegration.project_name == project_name)
        ).mappings().all()

        if slack_integrations:
            current_app.logger.info(f"Found {len(slack_integrations)} Slack integrations for project {project_name}")
            details_url = external_url_for('show_project_crash', project_name=crash["project_name"], crash_id=crash["crash_id"])

            current_app.logger.info(f"Generated Slack details URL for crash {crash['crash_id']}: {details_url}")

            for integration in slack_integrations:
                try:
                    slack_client = slack_sdk.WebClient(token=integration["slack_access_token"])

                    # Create Slack message
                    blocks = [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": "🚨 ESP Crash Detected"
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Project:* {crash['project_name']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Version:* {crash['project_ver']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Crash ID:* {crash['crash_id']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Channel:* #{integration['slack_channel_name']}"
                                }
                            ]
                        }
                    ]

                    # Add crash dump snippet if available
                    if dump and len(dump.strip()) > 0:
                        crash_snippet = dump[:1000]
                        if len(dump) > 1000:
                            crash_snippet += "..."

                        blocks.append({
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Crash Dump (first 1000 chars):*\n```{crash_snippet}```"
                            }
                        })

                    # Add action button
                    blocks.append({
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "View Details"
                                },
                                "url": details_url,
                                "action_id": "view_crash_details"
                            }
                        ]
                    })

                    response = slack_client.chat_postMessage(
                        channel=integration["slack_channel_id"],
                        blocks=blocks,
                        text=f"ESP Crash detected in {crash['project_name']} (v{crash['project_ver']})"
                    )

                    if response["ok"]:
                        current_app.logger.info(f"Successfully sent Slack notification to #{integration['slack_channel_name']} for crash {crash['crash_id']}")
                    else:
                        error_msg = response.get('error', 'Unknown error')
                        if error_msg == 'not_in_channel':
                            # Try to join the channel automatically (only works for public channels)
                            try:
                                join_response = slack_client.conversations_join(channel=integration["slack_channel_id"])
                                if join_response["ok"]:
                                    # Successfully joined, now try to send the message again
                                    retry_response = slack_client.chat_postMessage(
                                        channel=integration["slack_channel_id"],
                                        blocks=blocks,
                                        text=f"ESP Crash detected in {crash['project_name']} (v{crash['project_ver']})"
                                    )
                                    if retry_response["ok"]:
                                        current_app.logger.info(f"Auto-joined #{integration['slack_channel_name']} and sent crash notification for crash {crash['crash_id']}")
                                    else:
                                        current_app.logger.error(f"Joined #{integration['slack_channel_name']} but failed to send crash notification: {retry_response.get('error', 'Unknown error')}")
                                else:
                                    current_app.logger.error(f"Bot not in channel #{integration['slack_channel_name']} and could not auto-join for crash {crash['crash_id']}. Please invite the bot manually.")
                            except Exception as join_error:
                                current_app.logger.error(f"Bot not in channel #{integration['slack_channel_name']} and auto-join failed for crash {crash['crash_id']}: {join_error}")
                        else:
                            current_app.logger.error(f"Slack API returned error for #{integration['slack_channel_name']} crash {crash['crash_id']}: {error_msg}")

                except SlackApiError as e:
                    current_app.logger.error(f"Failed to send Slack notification to #{integration['slack_channel_name']} for crash {crash['crash_id']}: {e}")
                except Exception as e:
                    current_app.logger.error(f"Unexpected error sending Slack notification for crash {crash['crash_id']}: {e}")
        else:
            current_app.logger.info(f"No Slack integrations found for project {project_name}")

    # Non-AI duplicate-signature backfill: crashes that already have a dump
    # but predate this feature (or whose earlier signature attempt found no
    # parseable backtrace, e.g. a decode-failure dump - those legitimately
    # stay NULL and get harmlessly re-checked each tick). Pure local
    # computation, no external calls - unlike the AI step below there's no
    # cost or backlog-explosion concern, so a generous batch size just runs
    # the backlog down over a handful of ticks.
    backfill_targets = db.session.execute(
        select(Crash.crash_id, Crash.project_name, Crash.dump)
        .where(Crash.dump.is_not(None), Crash.signature.is_(None))
        .order_by(Crash.crash_id.desc())
        .limit(500)
    ).mappings().all()
    if backfill_targets:
        processed_anything = True
        for row in backfill_targets:
            signature = compute_signature(row["dump"])
            _upsert_relation(row["project_name"], signature)
            db.session.execute(
                update(Crash).where(Crash.crash_id == row["crash_id"])
                .values(signature=signature)
            )
        db.session.commit()
        current_app.logger.info(f"Backfilled signature for {len(backfill_targets)} crashes")

    # AI summary + tagging: a second, independent pass with its own retry
    # gate (ai_summary IS NULL), scoped to projects that have explicitly
    # granted the service identity ACL access - see app/ai_tagging.py. Gate
    # on every required config value, not just MCP_SERVICE_GITHUB_USER - a
    # partially-configured deployment would otherwise retry a doomed API
    # call every tick instead of a clean, informative no-op.
    #
    # No longer scoped to crashes after the grant date - now that a review
    # is written once per (project_name, signature) group rather than per
    # crash (see app/ai_tagging.py), granting access to a project only
    # means reviewing its handful of distinct relations, not backfilling
    # every historical crash.
    service_user = current_app.config.get("MCP_SERVICE_GITHUB_USER")
    ai_configured = bool(
        service_user
        and current_app.config.get("ANTHROPIC_API_KEY")
        and current_app.config.get("MCP_PUBLIC_URL")
        and current_app.config.get("MCP_SERVICE_TOKEN")
    )
    if service_user and not ai_configured:
        current_app.logger.warning(
            "MCP_SERVICE_GITHUB_USER is set but one of ANTHROPIC_API_KEY / "
            "MCP_PUBLIC_URL / MCP_SERVICE_TOKEN is not - skipping AI summarize/tag step"
        )
    if ai_configured:
        # One representative (most recent) crash per not-yet-reviewed
        # (project_name, signature) group, rather than per crash - the
        # review is written once per group (see app/ai_tagging.py), so
        # picking several crashes from the same backlog-heavy group would
        # waste API calls re-confirming "already reviewed" instead of
        # covering distinct issues.
        ai_crashes = db.session.execute(
            select(Crash.crash_id, Crash.project_name)
            .join(ProjectAuth, (Crash.project_name == ProjectAuth.project_name)
                                & (ProjectAuth.github == service_user))
            .join(CrashRelation, (CrashRelation.project_name == Crash.project_name)
                                  & (CrashRelation.signature == Crash.signature))
            .where(
                Crash.dump.is_not(None), Crash.signature.is_not(None),
                CrashRelation.ai_summary.is_(None),
            )
            .distinct(Crash.project_name, Crash.signature)
            .order_by(Crash.project_name, Crash.signature, Crash.date.desc())
            .limit(10)
        ).mappings().all()
        processed_anything = processed_anything or bool(ai_crashes)
        for crash in ai_crashes:
            try:
                summarize_and_tag(crash["crash_id"], crash["project_name"])
                current_app.logger.info(f"AI-summarized crash {crash['crash_id']}")
            except Exception as e:
                current_app.logger.error(f"AI summarize/tag failed for crash {crash['crash_id']}: {e}")

    if not processed_anything:
        return "Nothing to do\n", 200
    return "OK\n", 200


def register(app):
    app.add_url_rule('/cron', endpoint="cron", view_func=cron)
