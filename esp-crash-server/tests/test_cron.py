import os
import tempfile

import pytest

import helpers


def test_cron_no_pending_crashes(client):
    resp = client.get("/cron")
    assert resp.status_code == 200
    assert resp.data == b"Nothing to do\n"


def test_cron_ignores_crash_without_elf(client, db_conn):
    device_id = helpers.create_device(db_conn, "dev-cron-1")
    helpers.create_crash(db_conn, "proj-cron-noelf", "1.0", device_id)
    resp = client.get("/cron")
    assert resp.status_code == 200
    assert resp.data == b"Nothing to do\n"


def _fake_resolve(dump_path, prog_path):
    fd, core_elf = tempfile.mkstemp()
    os.close(fd)
    return ([], [], "base panic text\n", core_elf, [])


def test_cron_processes_pending_crash(client, db_conn, monkeypatch):
    from app import decode

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", _fake_resolve)

    device_id = helpers.create_device(db_conn, "dev-cron-2")
    helpers.create_elf_file(db_conn, "proj-cron-ok", "1.0")
    crash_id = helpers.create_crash(db_conn, "proj-cron-ok", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert resp.data == b"OK\n"

    with db_conn.cursor() as cur:
        cur.execute("SELECT dump FROM crash WHERE crash_id = %s", (crash_id,))
        assert "base panic text" in cur.fetchone()[0]


def test_cron_sends_webhook(client, db_conn, monkeypatch):
    import requests
    from app import decode

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", _fake_resolve)

    calls = []

    class FakeResponse:
        def raise_for_status(self):
            pass

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url, json))
        return FakeResponse()

    monkeypatch.setattr(requests, "post", fake_post)

    device_id = helpers.create_device(db_conn, "dev-cron-3")
    helpers.create_elf_file(db_conn, "proj-cron-wh", "1.0")
    helpers.create_crash(db_conn, "proj-cron-wh", "1.0", device_id, crash_dmp=b"raw-dump")
    helpers.create_webhook(db_conn, "proj-cron-wh", "https://hooks.test/notify")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert len(calls) == 1
    assert calls[0][0] == "https://hooks.test/notify"
    assert calls[0][1]["project_name"] == "proj-cron-wh"


def test_cron_sends_slack_notification(client, db_conn, monkeypatch):
    import slack_sdk
    from app import decode

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", _fake_resolve)

    posted = []

    class FakeSlack:
        def __init__(self, token=None):
            self.token = token

        def chat_postMessage(self, **kwargs):
            posted.append(kwargs)
            return {"ok": True}

    monkeypatch.setattr(slack_sdk, "WebClient", lambda token=None: FakeSlack(token=token))

    device_id = helpers.create_device(db_conn, "dev-cron-4")
    helpers.create_elf_file(db_conn, "proj-cron-slack", "1.0")
    helpers.create_crash(db_conn, "proj-cron-slack", "1.0", device_id, crash_dmp=b"raw-dump")
    helpers.create_slack_integration(db_conn, "proj-cron-slack")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert len(posted) == 1
    assert posted[0]["channel"] == "C123"


def _configure_ai(app):
    """Set every config value app/routes/cron.py requires before it will
    attempt the AI summarize/tag step - see test_cron_ai_summary_requires_full_config
    for what happens when only some of these are set."""
    app.config["MCP_SERVICE_GITHUB_USER"] = "esp-crash-bot"
    app.config["ANTHROPIC_API_KEY"] = "sk-test"
    app.config["MCP_PUBLIC_URL"] = "https://mcp-esp-crash.example"
    app.config["MCP_SERVICE_TOKEN"] = "svc-token"


def test_cron_ai_summary_scoped_to_granted_projects(client, db_conn, monkeypatch, app):
    from app import decode
    from app.routes import cron

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", _fake_resolve)
    calls = []
    monkeypatch.setattr(cron, "summarize_and_tag", lambda crash_id, project_name: calls.append((crash_id, project_name)))
    _configure_ai(app)

    device_id = helpers.create_device(db_conn, "dev-cron-ai-1")
    helpers.create_project(db_conn, "proj-cron-ai-granted", github_user="esp-crash-bot")
    helpers.create_elf_file(db_conn, "proj-cron-ai-granted", "1.0")
    granted_crash = helpers.create_crash(db_conn, "proj-cron-ai-granted", "1.0", device_id, crash_dmp=b"raw-dump")

    # No project_auth grant for esp-crash-bot on this project - must be skipped.
    helpers.create_elf_file(db_conn, "proj-cron-ai-ungranted", "1.0")
    helpers.create_crash(db_conn, "proj-cron-ai-ungranted", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert calls == [(granted_crash, "proj-cron-ai-granted")]


def test_cron_ai_summary_skips_already_summarized(client, db_conn, monkeypatch, app):
    from app import decode
    from app.routes import cron

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", _fake_resolve)
    calls = []
    monkeypatch.setattr(cron, "summarize_and_tag", lambda crash_id, project_name: calls.append(crash_id))
    _configure_ai(app)

    device_id = helpers.create_device(db_conn, "dev-cron-ai-2")
    helpers.create_project(db_conn, "proj-cron-ai-done", github_user="esp-crash-bot")
    helpers.create_elf_file(db_conn, "proj-cron-ai-done", "1.0")
    helpers.create_crash(
        db_conn, "proj-cron-ai-done", "1.0", device_id,
        dump="already symbolicated", ai_summary="already summarized",
    )

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert calls == []


def test_cron_ai_summary_failure_is_logged_and_skipped(client, db_conn, monkeypatch, app):
    from app import decode
    from app.routes import cron

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", _fake_resolve)

    def failing_summarize(crash_id, project_name):
        raise RuntimeError("boom")

    monkeypatch.setattr(cron, "summarize_and_tag", failing_summarize)
    _configure_ai(app)

    device_id = helpers.create_device(db_conn, "dev-cron-ai-3")
    helpers.create_project(db_conn, "proj-cron-ai-fail", github_user="esp-crash-bot")
    helpers.create_elf_file(db_conn, "proj-cron-ai-fail", "1.0")
    crash_id = helpers.create_crash(db_conn, "proj-cron-ai-fail", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert resp.data == b"OK\n"

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_summary FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] is None


def test_cron_ai_summary_requires_full_config(client, db_conn, monkeypatch, app):
    """MCP_SERVICE_GITHUB_USER alone isn't enough - a partially configured
    deployment (e.g. ANTHROPIC_API_KEY not yet set) must not call the AI
    step at all, let alone crash or spin retrying a doomed call."""
    from app import decode
    from app.routes import cron

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", _fake_resolve)
    calls = []
    monkeypatch.setattr(cron, "summarize_and_tag", lambda crash_id, project_name: calls.append(crash_id))

    app.config["MCP_SERVICE_GITHUB_USER"] = "esp-crash-bot"
    app.config["ANTHROPIC_API_KEY"] = ""
    app.config["MCP_PUBLIC_URL"] = ""
    app.config["MCP_SERVICE_TOKEN"] = ""

    device_id = helpers.create_device(db_conn, "dev-cron-ai-4")
    helpers.create_project(db_conn, "proj-cron-ai-partial", github_user="esp-crash-bot")
    helpers.create_elf_file(db_conn, "proj-cron-ai-partial", "1.0")
    helpers.create_crash(db_conn, "proj-cron-ai-partial", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert resp.data == b"OK\n"
    assert calls == []


def test_cron_ai_summary_no_op_when_entirely_unconfigured(client, db_conn, monkeypatch, app):
    """The default, out-of-the-box state (nobody has set any of the four AI
    env vars): cron must behave exactly as it did before this feature -
    normal symbolication, no AI calls, no errors."""
    from app import decode
    from app.routes import cron

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", _fake_resolve)
    calls = []
    monkeypatch.setattr(cron, "summarize_and_tag", lambda crash_id, project_name: calls.append(crash_id))

    for key in ("MCP_SERVICE_GITHUB_USER", "ANTHROPIC_API_KEY", "MCP_PUBLIC_URL", "MCP_SERVICE_TOKEN"):
        app.config[key] = ""

    device_id = helpers.create_device(db_conn, "dev-cron-ai-5")
    helpers.create_elf_file(db_conn, "proj-cron-ai-unconfigured", "1.0")
    crash_id = helpers.create_crash(db_conn, "proj-cron-ai-unconfigured", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert resp.data == b"OK\n"
    assert calls == []

    # symbolication itself is unaffected
    with db_conn.cursor() as cur:
        cur.execute("SELECT dump FROM crash WHERE crash_id = %s", (crash_id,))
        assert "base panic text" in cur.fetchone()[0]


@pytest.mark.integration
def test_cron_real_gdb_decode_path():
    """Requires the real xtensa ESP toolchain gdb (only present in the
    Docker toolchain image). Not runnable in a plain dev environment - see
    decode_module_coredump.py / test_decode_module_coredump.py for the
    already-covered pure parsing logic this depends on."""
    pytest.skip("requires real ESP toolchain gdb; run inside the toolchain container")
