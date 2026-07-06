"""Cron-polled crash processing: symbolication, webhook, and Slack
notification dispatch. Mechanical move from server.py - logic unchanged,
endpoint name preserved exactly (registered directly on the app object, not
via Flask Blueprint - see core.py for why). Deliberately un-authenticated
and polled via HTTP by a sidecar container (see docker-compose.yml `cron`
service) rather than a real cron/celery job - kept as-is for this phase."""
import os
import bz2
import tempfile

import requests
import slack_sdk
from flask import current_app
from slack_sdk.errors import SlackApiError

import decode_module_coredump as mod_decoder
from .. import decode
from ..db import ldb
from ..rendering import external_url_for


def cron():
    """Process pending crash dumps and send webhooks."""

    c = ldb().cursor()
    # Fetch all crashes from database that has not been processed
    crashes = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, crash.project_ver, crash.crash_dmp
        FROM
            crash
        WHERE
            dump IS NULL AND
            (select count(e.elf_file_id) from elf_file as e where e.project_name = crash.project_name and e.project_ver = crash.project_ver) > 0
        ORDER BY
            crash.crash_id DESC
        LIMIT 10
        """)
    # If no crash data is found, return "Not found"
    if len(crashes) < 1:
        return "Nothing to do\n", 200

    current_app.logger.info("Processing {} crashes".format(len(crashes)))
    for crash in crashes:
        current_app.logger.info("Processing crash {} project_name '{}' date '{}'".format(crash["crash_id"], crash["project_name"], crash["date"]))

        # Fetch all elf image data from database that matches this project and version
        elf_images = ldb().get_data("SELECT elf_file_id, date, project_name, project_ver, elf_file FROM elf_file WHERE project_name = %s AND project_ver = %s ORDER BY date DESC", (crash["project_name"], crash["project_ver"], ))

        dump = ""
        if len(elf_images) < 1:
            current_app.logger.info("  No elf_file found")
            continue

        last_module_map = []
        for elf_image in elf_images:
            dmp = tempfile.NamedTemporaryFile(delete=False)
            elf = tempfile.NamedTemporaryFile(delete=False)
            try:
                decompressed_crash_dmp = bz2.decompress(crash["crash_dmp"])
            except IOError:
                decompressed_crash_dmp = crash["crash_dmp"]
            try:
                decompressed_elf_file = bz2.decompress(elf_image["elf_file"])
            except IOError:
                decompressed_elf_file = elf_image["elf_file"]
            dmp.write(decompressed_crash_dmp); dmp.close()
            elf.write(decompressed_elf_file); elf.close()

            # Read the registry (plain gdb) and resolve module ELFs by sha1.
            regs, loaded, base_text, core_elf, mod_status = \
                decode._resolve_modules_for_dump(ldb(), dmp.name, elf.name)
            last_module_map = [{"name": r["name"], "version": r.get("version", ""), "sha1": r["sha1"]} for r in regs]
            try:
                for line in mod_status:
                    dump += line + "\n"
                if loaded:
                    # Re-run esp-coredump with a literal add-symbol-file gdbinit so
                    # its full report resolves the module frames inline.
                    dump += mod_decoder.symbolicated_report(dmp.name, elf.name, loaded)
                else:
                    dump += base_text
            finally:
                for m in loaded:
                    try:
                        os.remove(m["elf"])
                    except OSError:
                        pass
                for path in (core_elf, dmp.name, elf.name):
                    try:
                        os.remove(path)
                    except OSError:
                        pass

        from psycopg2.extras import Json
        module_names = [m["name"] for m in last_module_map]
        c.execute(
            "UPDATE crash SET dump = %s, module_names = %s, module_map = %s WHERE crash_id = %s",
            (dump, module_names, Json(last_module_map), crash["crash_id"]),
        )
        ldb().commit()
        current_app.logger.info("Updated crash {} (modules: {})".format(crash["crash_id"], module_names))

        # Send webhooks
        project_name = crash["project_name"]
        webhooks = ldb().get_data("SELECT webhook_url FROM project_webhooks WHERE project_name = %s", (project_name,))

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
        slack_integrations = ldb().get_data("""
            SELECT slack_access_token, slack_channel_id, slack_channel_name
            FROM project_slack_integrations
            WHERE project_name = %s
        """, (project_name,))

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


    # return just a 200 OK
    return "OK\n", 200


def register(app):
    app.add_url_rule('/cron', endpoint="cron", view_func=cron)
