import os
import tempfile
from datetime import datetime, timedelta

import pytest

import helpers


@pytest.fixture(autouse=True)
def _decode_service_configured(monkeypatch):
    """Cron has no in-process decoder any more, so it declines to decode when
    the service is not configured. These tests patch the client itself, but
    still have to look configured for the loop to run."""
    monkeypatch.setenv("DECODE_SERVICE_URL", "http://gdb.internal:8002")
    monkeypatch.setenv("DECODE_SERVICE_TOKEN", "tok")


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


def _result(report, modules=()):
    """The shape POST /v1/decode returns."""
    return {"report": report, "modules": list(modules),
            "module_names": [m["name"] for m in modules],
            "toolchain": "xtensa-esp32", "toolchain_source": "default",
            "elf_file_id": 1, "elf_count": 1}


def _fake_resolve(crash_id, **kwargs):
    return _result("base panic text\n")


def test_cron_processes_pending_crash(client, db_conn, monkeypatch):
    from app import decode_client

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve)

    device_id = helpers.create_device(db_conn, "dev-cron-2")
    helpers.create_elf_file(db_conn, "proj-cron-ok", "1.0")
    crash_id = helpers.create_crash(db_conn, "proj-cron-ok", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert resp.data == b"OK\n"

    with db_conn.cursor() as cur:
        cur.execute("SELECT dump FROM crash WHERE crash_id = %s", (crash_id,))
        assert "base panic text" in cur.fetchone()[0]


_STACK_TEXT = (
    "==================== CURRENT THREAD STACK =====================\n"
    "#0  panic_abort (details=0x3ffb37ac) at panic.c:489\n"
    "#1  0x4008874c in esp_system_abort (details=0x3ffb37ac) at esp_system_chip.c:87\n"
    "#2  0x40114e3c in watchdog_timer_isr_callback (timer=0x3ffd1108) at watchdog.c:330\n"
    "======================== THREADS INFO =========================\n"
)


def _fake_resolve_with_stack(crash_id, **kwargs):
    return _result(_STACK_TEXT)


def test_cron_computes_signature_on_symbolication(client, db_conn, monkeypatch):
    from app import decode_client

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve_with_stack)

    device_id = helpers.create_device(db_conn, "dev-cron-sig")
    helpers.create_elf_file(db_conn, "proj-cron-sig", "1.0")
    crash_id = helpers.create_crash(db_conn, "proj-cron-sig", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT signature FROM crash WHERE crash_id = %s", (crash_id,))
        signature = cur.fetchone()[0]
        assert signature is not None
        assert len(signature) == 64


def test_cron_creates_relation_when_signature_first_assigned(client, db_conn, monkeypatch):
    """crash.signature has an FK to crash_relation - the relation row must
    exist before (or in the same transaction as) the crash is given that
    signature."""
    from app import decode_client

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve_with_stack)

    device_id = helpers.create_device(db_conn, "dev-cron-sig-relation")
    helpers.create_elf_file(db_conn, "proj-cron-sig-relation", "1.0")
    crash_id = helpers.create_crash(db_conn, "proj-cron-sig-relation", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT signature FROM crash WHERE crash_id = %s", (crash_id,))
        signature = cur.fetchone()[0]
        assert signature is not None
        cur.execute(
            "SELECT COUNT(*) FROM crash_relation WHERE project_name = %s AND signature = %s",
            ("proj-cron-sig-relation", signature),
        )
        assert cur.fetchone()[0] == 1


def test_cron_backfills_signature_for_already_symbolicated_crashes(client, db_conn, monkeypatch):
    from app import decode_client

    # Backfill must not re-run symbolication - if it did, this would blow up.
    def _fail(*a, **k):
        raise AssertionError("backfill should not re-symbolicate")

    monkeypatch.setattr(decode_client, "decode_crash", _fail)

    device_id = helpers.create_device(db_conn, "dev-cron-sig-backfill")
    crash_id = helpers.create_crash(
        db_conn, "proj-cron-sig-backfill", "1.0", device_id, dump=_STACK_TEXT,
    )

    resp = client.get("/cron")
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT signature FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] is not None


def test_cron_backfill_leaves_unparseable_dump_signature_null(client, db_conn):
    device_id = helpers.create_device(db_conn, "dev-cron-sig-unparseable")
    crash_id = helpers.create_crash(
        db_conn, "proj-cron-sig-unparseable", "1.0", device_id, dump="Failed to load core dump.",
    )

    resp = client.get("/cron")
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT signature FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] is None


def test_cron_backfill_attempts_an_unparseable_dump_only_once(client, db_conn):
    """The backfill must terminate. A dump with no parseable backtrace yields
    NULL every time, so it has to be marked as attempted - otherwise it is
    re-selected on every tick forever, and because the query is ordered
    `crash_id DESC` the newest such rows permanently starve the backlog
    behind them (the bug this column was added to fix)."""
    device_id = helpers.create_device(db_conn, "dev-cron-sig-attempt-once")
    crash_id = helpers.create_crash(
        db_conn, "proj-cron-sig-attempt-once", "1.0", device_id,
        dump="Failed to load core dump.",
    )

    assert client.get("/cron").status_code == 200
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT signature, signature_attempted_at FROM crash WHERE crash_id = %s",
            (crash_id,))
        signature, first_attempt = cur.fetchone()
    assert signature is None
    assert first_attempt is not None, "an attempt that found nothing must still be stamped"

    # A second tick must not pick the row up again: same timestamp means it
    # was never re-selected, let alone re-written.
    assert client.get("/cron").status_code == 200
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT signature_attempted_at FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == first_attempt


def test_cron_backfill_stamps_the_attempt_when_it_succeeds(client, db_conn, monkeypatch):
    from app import decode_client

    monkeypatch.setattr(decode_client, "decode_crash",
                        lambda *a, **k: pytest.fail("backfill should not re-symbolicate"))

    device_id = helpers.create_device(db_conn, "dev-cron-sig-stamp")
    crash_id = helpers.create_crash(
        db_conn, "proj-cron-sig-stamp", "1.0", device_id, dump=_STACK_TEXT,
    )

    assert client.get("/cron").status_code == 200
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT signature, signature_attempted_at FROM crash WHERE crash_id = %s",
            (crash_id,))
        signature, attempted = cur.fetchone()
    assert signature is not None
    assert attempted is not None


def test_cron_sends_webhook(client, db_conn, monkeypatch):
    import requests
    from app import decode_client

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve)

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
    from app import decode_client

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve)

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
    from app import decode_client
    from app.routes import cron

    # AI-review selection now requires a signature - use the fake resolver
    # that produces a parseable stack, so cron's own symbolication pass
    # (which runs before the AI pass, same request) computes one and
    # creates the crash_relation row for it.
    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve_with_stack)
    calls = []
    monkeypatch.setattr(cron, "summarize_and_tag", lambda crash_id, project_name: calls.append((crash_id, project_name)))
    _configure_ai(app)

    device_id = helpers.create_device(db_conn, "dev-cron-ai-1")
    helpers.create_project(db_conn, "proj-cron-ai-granted", github_user="esp-crash-bot", date=datetime.utcnow() - timedelta(hours=1))
    helpers.create_elf_file(db_conn, "proj-cron-ai-granted", "1.0")
    granted_crash = helpers.create_crash(db_conn, "proj-cron-ai-granted", "1.0", device_id, crash_dmp=b"raw-dump")

    # No project_auth grant for esp-crash-bot on this project - must be skipped.
    helpers.create_elf_file(db_conn, "proj-cron-ai-ungranted", "1.0")
    helpers.create_crash(db_conn, "proj-cron-ai-ungranted", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert calls == [(granted_crash, "proj-cron-ai-granted")]


def test_cron_ai_summary_includes_pre_grant_backlog(client, db_conn, monkeypatch, app):
    """Granting esp-crash-bot access to a project no longer excludes crash
    history from before the grant - now that a review is written once per
    (project_name, signature) group rather than per crash, granting access
    only means reviewing a project's handful of distinct relations, not
    backfilling every historical crash."""
    from app import decode_client
    from app.routes import cron

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve)
    calls = []
    monkeypatch.setattr(cron, "summarize_and_tag", lambda crash_id, project_name: calls.append(crash_id))

    grant_time = datetime.utcnow()
    helpers.create_project(db_conn, "proj-cron-ai-backlog", github_user="esp-crash-bot", date=grant_time)
    _configure_ai(app)

    device_id = helpers.create_device(db_conn, "dev-cron-ai-backlog")
    helpers.create_elf_file(db_conn, "proj-cron-ai-backlog", "1.0")

    # Already-symbolicated crash from before the grant - now eligible too.
    old_crash = helpers.create_crash(
        db_conn, "proj-cron-ai-backlog", "1.0", device_id, crash_dmp=b"raw-dump",
        dump="old crash, already symbolicated", date=grant_time - timedelta(days=30),
        signature="1" * 64,
    )
    # New, already-symbolicated crash from after the grant - also eligible.
    new_crash = helpers.create_crash(
        db_conn, "proj-cron-ai-backlog", "1.0", device_id, crash_dmp=b"raw-dump",
        dump="new crash, already symbolicated", date=grant_time + timedelta(hours=1),
        signature="2" * 64,
    )

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert set(calls) == {old_crash, new_crash}


def test_cron_ai_summary_skips_already_summarized(client, db_conn, monkeypatch, app):
    from app import decode_client
    from app.routes import cron

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve)
    calls = []
    monkeypatch.setattr(cron, "summarize_and_tag", lambda crash_id, project_name: calls.append(crash_id))
    _configure_ai(app)

    device_id = helpers.create_device(db_conn, "dev-cron-ai-2")
    helpers.create_project(db_conn, "proj-cron-ai-done", github_user="esp-crash-bot", date=datetime.utcnow() - timedelta(hours=1))
    helpers.create_elf_file(db_conn, "proj-cron-ai-done", "1.0")
    helpers.create_crash(
        db_conn, "proj-cron-ai-done", "1.0", device_id,
        dump="already symbolicated", signature="3" * 64,
        ai_title="already summarized", ai_summary="already summarized",
    )

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert calls == []


def test_cron_ai_summary_failure_is_logged_and_skipped(client, db_conn, monkeypatch, app):
    from app import decode_client
    from app.routes import cron

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve_with_stack)

    def failing_summarize(crash_id, project_name):
        raise RuntimeError("boom")

    monkeypatch.setattr(cron, "summarize_and_tag", failing_summarize)
    _configure_ai(app)

    device_id = helpers.create_device(db_conn, "dev-cron-ai-3")
    helpers.create_project(db_conn, "proj-cron-ai-fail", github_user="esp-crash-bot", date=datetime.utcnow() - timedelta(hours=1))
    helpers.create_elf_file(db_conn, "proj-cron-ai-fail", "1.0")
    crash_id = helpers.create_crash(db_conn, "proj-cron-ai-fail", "1.0", device_id, crash_dmp=b"raw-dump")

    resp = client.get("/cron")
    assert resp.status_code == 200
    assert resp.data == b"OK\n"

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT ai_summary FROM crash_relation WHERE project_name = %s",
            ("proj-cron-ai-fail",),
        )
        assert cur.fetchone()[0] is None


def test_cron_ai_summary_requires_full_config(client, db_conn, monkeypatch, app):
    """MCP_SERVICE_GITHUB_USER alone isn't enough - a partially configured
    deployment (e.g. ANTHROPIC_API_KEY not yet set) must not call the AI
    step at all, let alone crash or spin retrying a doomed call."""
    from app import decode_client
    from app.routes import cron

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve)
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
    from app import decode_client
    from app.routes import cron

    monkeypatch.setattr(decode_client, "decode_crash", _fake_resolve)
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
