import helpers


class FakeSlackClient:
    """Stand-in for slack_sdk.WebClient - configure canned dict responses per
    method call so routes never make real network calls."""

    def __init__(self, token=None, **responses):
        self.token = token
        self._responses = responses

    def conversations_list(self, **kwargs):
        return self._responses.get("conversations_list", {"ok": True, "channels": []})

    def conversations_info(self, **kwargs):
        return self._responses.get("conversations_info", {"ok": True, "channel": {"name": "general", "is_member": True}})

    def conversations_join(self, **kwargs):
        return self._responses.get("conversations_join", {"ok": True})

    def chat_postMessage(self, **kwargs):
        return self._responses.get("chat_postMessage", {"ok": True, "ts": "123.456"})

    def auth_test(self, **kwargs):
        return self._responses.get("auth_test", {"ok": True, "user_id": "U1", "team": "T1", "user": "bot"})


def _patch_webclient(monkeypatch, **responses):
    import slack_sdk

    monkeypatch.setattr(slack_sdk, "WebClient", lambda token=None: FakeSlackClient(token=token, **responses))


# --- slack_auth -----------------------------------------------------------

def test_slack_auth_forbidden_for_unregistered_project(client):
    resp = client.get("/projects/no-such-project/slack/auth")
    assert resp.status_code == 403


def test_slack_auth_redirects_to_slack_oauth(client, db_conn):
    helpers.create_project(db_conn, "proj-slack", github_user="none")
    resp = client.get("/projects/proj-slack/slack/auth")
    assert resp.status_code == 302
    assert "slack.com/oauth" in resp.headers["Location"]


# --- slack_callback ---------------------------------------------------------

def test_slack_callback_error_param(client):
    resp = client.get("/slack/callback?error=access_denied")
    assert resp.status_code == 400


def test_slack_callback_missing_code(client):
    resp = client.get("/slack/callback")
    assert resp.status_code == 400


def test_slack_callback_missing_project_session(client):
    resp = client.get("/slack/callback?code=abc123")
    assert resp.status_code == 400


def test_slack_callback_success(client, monkeypatch):
    import requests

    with client.session_transaction() as sess:
        sess["slack_auth_project"] = "proj-cb"

    class FakeResp:
        def json(self):
            return {"ok": True, "access_token": "xoxb-fake", "team": {"id": "T1", "name": "Team1"}}

    monkeypatch.setattr(requests, "post", lambda *a, **kw: FakeResp())

    resp = client.get("/slack/callback?code=abc123")
    assert resp.status_code == 302
    assert "channel-selection" in resp.headers["Location"]


# --- handle_slack_interactivity ---------------------------------------------

def test_slack_interactive_block_action(client):
    import json

    payload = json.dumps({"type": "block_actions", "actions": [{"action_id": "view_crash_details"}]})
    resp = client.post("/slack/interactive", data={"payload": payload})
    assert resp.status_code == 200


def test_slack_interactive_malformed_payload_still_200(client):
    resp = client.post("/slack/interactive", data={"payload": "not-json"})
    assert resp.status_code == 200


# --- slack_channel_selection (GET) ------------------------------------------

def test_channel_selection_requires_oauth_session(client, db_conn):
    helpers.create_project(db_conn, "proj-cs", github_user="none")
    resp = client.get("/projects/proj-cs/slack/channel-selection")
    assert resp.status_code == 400


def test_channel_selection_renders_channels(client, db_conn, monkeypatch):
    helpers.create_project(db_conn, "proj-cs2", github_user="none")
    with client.session_transaction() as sess:
        sess["slack_oauth_data"] = {
            "access_token": "xoxb-fake",
            "team_id": "T1",
            "team_name": "Team1",
            "project_name": "proj-cs2",
        }
    _patch_webclient(
        monkeypatch,
        conversations_list={"ok": True, "channels": [{"id": "C1", "name": "general", "is_member": True}]},
    )
    resp = client.get("/projects/proj-cs2/slack/channel-selection")
    assert resp.status_code == 200
    assert b"general" in resp.data


# --- slack_channel_selection (POST) -----------------------------------------

def test_channel_selection_post_missing_channel(client, db_conn):
    helpers.create_project(db_conn, "proj-cs3", github_user="none")
    with client.session_transaction() as sess:
        sess["slack_oauth_data"] = {
            "access_token": "xoxb-fake", "team_id": "T1", "team_name": "Team1", "project_name": "proj-cs3",
        }
    resp = client.post("/projects/proj-cs3/slack/channel-selection", data={})
    assert resp.status_code == 400


def test_channel_selection_post_creates_integration(client, db_conn):
    helpers.create_project(db_conn, "proj-cs4", github_user="none")
    with client.session_transaction() as sess:
        sess["slack_oauth_data"] = {
            "access_token": "xoxb-fake", "team_id": "T1", "team_name": "Team1", "project_name": "proj-cs4",
        }
    resp = client.post(
        "/projects/proj-cs4/slack/channel-selection",
        data={"channel_id": "C1", "channel_name": "general"},
    )
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT slack_channel_name FROM project_slack_integrations WHERE project_name = %s",
            ("proj-cs4",),
        )
        assert cur.fetchone()[0] == "general"


# --- delete / update slack integration --------------------------------------

def test_delete_slack_integration(client, db_conn):
    helpers.create_project(db_conn, "proj-sd", github_user="none")
    integration_id = helpers.create_slack_integration(db_conn, "proj-sd")

    resp = client.get(f"/projects/proj-sd/slack/{integration_id}/delete")
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM project_slack_integrations WHERE slack_integration_id = %s", (integration_id,)
        )
        assert cur.fetchone() is None


def test_update_slack_channel_missing_data(client, db_conn):
    helpers.create_project(db_conn, "proj-su", github_user="none")
    integration_id = helpers.create_slack_integration(db_conn, "proj-su")
    resp = client.post(f"/projects/proj-su/slack/{integration_id}/update_channel", data={})
    assert resp.status_code == 400


def test_update_slack_channel_success(client, db_conn):
    helpers.create_project(db_conn, "proj-su2", github_user="none")
    integration_id = helpers.create_slack_integration(db_conn, "proj-su2")
    resp = client.post(
        f"/projects/proj-su2/slack/{integration_id}/update_channel",
        data={"channel_id": "C2", "channel_name": "random"},
    )
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT slack_channel_name FROM project_slack_integrations WHERE slack_integration_id = %s",
            (integration_id,),
        )
        assert cur.fetchone()[0] == "random"


# --- test_slack_integration / verify_slack_integration ----------------------

def test_slack_test_integration_no_integrations_404(client, db_conn):
    helpers.create_project(db_conn, "proj-ti", github_user="none")
    resp = client.get("/projects/proj-ti/slack/test")
    assert resp.status_code == 404


def test_slack_test_integration_success(client, db_conn, monkeypatch):
    helpers.create_project(db_conn, "proj-ti2", github_user="none")
    helpers.create_slack_integration(db_conn, "proj-ti2")
    _patch_webclient(monkeypatch)
    resp = client.get("/projects/proj-ti2/slack/test")
    assert resp.status_code == 200
    assert b"Successfully sent test message" in resp.data


def test_verify_slack_integration_no_integrations(client, db_conn):
    helpers.create_project(db_conn, "proj-vi", github_user="none")
    resp = client.get("/projects/proj-vi/slack/verify")
    assert resp.status_code == 200
    assert b"No Slack integrations found" in resp.data


def test_verify_slack_integration_success(client, db_conn, monkeypatch):
    helpers.create_project(db_conn, "proj-vi2", github_user="none")
    helpers.create_slack_integration(db_conn, "proj-vi2")
    _patch_webclient(monkeypatch)
    resp = client.get("/projects/proj-vi2/slack/verify")
    assert resp.status_code == 200
    assert b"Auth test passed" in resp.data
