"""GET /api/v1/projects/<name>/settings (composite) plus the per-section
ACL, webhook, device-url-template, and Slack-integration endpoints
mcp_app/tools.py backs.

Slack verify/test are the one deviation from that pattern: they make live
Slack API calls rather than ACL-scoped DB CRUD, so they're implemented
directly here against slack_sdk - JSON counterparts of
app/routes/slack.py:verify_slack_integration/test_slack_integration (
structured results, not that route's emoji debug-log strings), gated by
the same auth_filter helper those HTML routes already use rather than
mcp_app/tools.py.
"""
import slack_sdk
from apiflask import abort
from flask import session
from sqlalchemy import select

from mcp_app import tools

from ..auth import api_login_required, auth_filter
from ..models import ProjectAuth, ProjectSlackIntegration, db
from . import api_v1
from .schema import not_found_if_none
from .schemas import (
    AclAddInSchema, AclSchema, DeviceUrlTemplateInSchema, ProjectSettingsSchema,
    SlackChannelInSchema, SlackIntegrationSchema, WebhookAddInSchema, WebhookSchema,
)


def _require_project_access(project_name):
    allowed = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).first()
    if not allowed:
        abort(404, message="Project not found or not accessible")


@api_v1.get("/projects/<project_name>/settings")
@api_v1.output(ProjectSettingsSchema)
@api_login_required
def get_project_settings(project_name):
    """Composite read for a settings screen: ACL + webhooks + Slack
    integrations + device-url-template in one call."""
    return not_found_if_none(
        tools.get_project_settings(session["gh_user"], project_name), "Project not found or not accessible"
    )


@api_v1.get("/projects/<project_name>/acl")
@api_v1.output(AclSchema(many=True))
@api_login_required
def list_acl(project_name):
    """Users granted access to a project."""
    return not_found_if_none(tools.list_acl(session["gh_user"], project_name), "Project not found or not accessible")


@api_v1.post("/projects/<project_name>/acl")
@api_v1.input(AclAddInSchema)
@api_login_required
def add_acl(project_name, json_data):
    """Grant a GitHub user access to a project the caller already has
    access to."""
    result = tools.add_acl(session["gh_user"], project_name, json_data["github"])
    if not result["added"]:
        reason = result.get("reason")
        status = 409 if reason == "already exists" else 403 if reason == "forbidden" else 400
        abort(status, message=reason or "could not add")
    return result, 201


@api_v1.delete("/projects/<project_name>/acl/<github>")
@api_login_required
def remove_acl(project_name, github):
    """Revoke a GitHub user's access to a project."""
    result = tools.remove_acl(session["gh_user"], project_name, github)
    if not result["removed"]:
        abort(404, message="ACL entry not found or not accessible")
    return result


@api_v1.get("/projects/<project_name>/webhooks")
@api_v1.output(WebhookSchema(many=True))
@api_login_required
def list_webhooks(project_name):
    """Webhook URLs notified when a new crash is processed for this
    project."""
    return not_found_if_none(tools.list_webhooks(session["gh_user"], project_name), "Project not found or not accessible")


@api_v1.post("/projects/<project_name>/webhooks")
@api_v1.input(WebhookAddInSchema)
@api_login_required
def add_webhook(project_name, json_data):
    """Register a new webhook URL for a project."""
    result = tools.add_webhook(session["gh_user"], project_name, json_data["webhook_url"])
    if not result["added"]:
        reason = result.get("reason")
        status = 409 if reason == "already exists" else 403 if reason == "forbidden" else 400
        abort(status, message=reason or "could not add")
    return result, 201


@api_v1.delete("/projects/<project_name>/webhooks/<int:webhook_id>")
@api_login_required
def remove_webhook(project_name, webhook_id):
    """Remove a webhook from a project."""
    result = tools.remove_webhook(session["gh_user"], project_name, webhook_id)
    if not result["removed"]:
        abort(404, message="Webhook not found or not accessible")
    return result


@api_v1.get("/projects/<project_name>/settings/device-url")
@api_login_required
def get_device_url_template(project_name):
    """The per-project device-id URL template (see device_url.py) - powers
    the "open external device page" link on crash rows."""
    return not_found_if_none(
        tools.get_device_url_template(session["gh_user"], project_name), "Project not found or not accessible"
    )


@api_v1.put("/projects/<project_name>/settings/device-url")
@api_v1.input(DeviceUrlTemplateInSchema)
@api_login_required
def set_device_url_template(project_name, json_data):
    """Set (or clear, with a blank template) the per-project device-id URL
    template. Must contain the {device_id} placeholder and use http(s)."""
    result = tools.set_device_url_template(session["gh_user"], project_name, json_data["device_url_template"])
    if not result["updated"]:
        reason = result.get("reason")
        status = 403 if reason == "forbidden" else 400
        abort(status, message=reason or "invalid template")
    return result


@api_v1.get("/projects/<project_name>/slack")
@api_v1.output(SlackIntegrationSchema(many=True))
@api_login_required
def list_slack_integrations(project_name):
    """Slack integrations for a project - never includes the access
    token."""
    return not_found_if_none(
        tools.list_slack_integrations(session["gh_user"], project_name), "Project not found or not accessible"
    )


@api_v1.delete("/projects/<project_name>/slack/<int:integration_id>")
@api_login_required
def remove_slack_integration(project_name, integration_id):
    """Delete a Slack integration."""
    result = tools.remove_slack_integration(session["gh_user"], project_name, integration_id)
    if not result["removed"]:
        abort(404, message="Slack integration not found or not accessible")
    return result


@api_v1.patch("/projects/<project_name>/slack/<int:integration_id>")
@api_v1.input(SlackChannelInSchema)
@api_login_required
def set_slack_channel(project_name, integration_id, json_data):
    """Change the channel an existing Slack integration posts to."""
    result = tools.set_slack_channel(
        session["gh_user"], project_name, integration_id, json_data["channel_id"], json_data["channel_name"]
    )
    if not result["updated"]:
        abort(404, message="Slack integration not found or not accessible")
    return result


@api_v1.get("/projects/<project_name>/slack/verify")
@api_login_required
def verify_slack_integration(project_name):
    """Live auth_test + conversations_info check per Slack integration."""
    _require_project_access(project_name)
    integrations = db.session.execute(
        select(
            ProjectSlackIntegration.slack_integration_id, ProjectSlackIntegration.slack_access_token,
            ProjectSlackIntegration.slack_channel_id, ProjectSlackIntegration.slack_channel_name,
            ProjectSlackIntegration.slack_team_name,
        ).where(ProjectSlackIntegration.project_name == project_name)
    ).mappings().all()

    results = []
    for integration in integrations:
        entry = {
            "integration_id": integration["slack_integration_id"],
            "team_name": integration["slack_team_name"],
            "channel_name": integration["slack_channel_name"],
            "auth_ok": False,
            "channel_ok": False,
            "error": None,
        }
        try:
            client = slack_sdk.WebClient(token=integration["slack_access_token"])
            auth_test = client.auth_test()
            entry["auth_ok"] = bool(auth_test["ok"])
            if entry["auth_ok"]:
                channel_info = client.conversations_info(channel=integration["slack_channel_id"])
                entry["channel_ok"] = bool(channel_info["ok"])
                if not entry["channel_ok"]:
                    entry["error"] = channel_info.get("error")
            else:
                entry["error"] = auth_test.get("error")
        except Exception as e:
            entry["error"] = str(e)
        results.append(entry)

    return {"project_name": project_name, "integrations": results}


@api_v1.post("/projects/<project_name>/slack/test")
@api_login_required
def test_slack_integration(project_name):
    """Send a real test message to each of the project's Slack channels."""
    _require_project_access(project_name)
    integrations = db.session.execute(
        select(
            ProjectSlackIntegration.slack_integration_id, ProjectSlackIntegration.slack_access_token,
            ProjectSlackIntegration.slack_channel_id, ProjectSlackIntegration.slack_channel_name,
        ).where(ProjectSlackIntegration.project_name == project_name)
    ).mappings().all()
    if not integrations:
        abort(404, message="No Slack integrations found for this project")

    results = []
    for integration in integrations:
        entry = {
            "integration_id": integration["slack_integration_id"],
            "channel_name": integration["slack_channel_name"],
            "ok": False,
            "error": None,
        }
        try:
            client = slack_sdk.WebClient(token=integration["slack_access_token"])
            response = client.chat_postMessage(
                channel=integration["slack_channel_id"],
                text=f"ESP-Crash test message for {project_name}",
            )
            entry["ok"] = bool(response["ok"])
            if not entry["ok"]:
                entry["error"] = response.get("error")
        except Exception as e:
            entry["error"] = str(e)
        results.append(entry)

    return {"project_name": project_name, "results": results}
