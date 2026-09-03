"""The decode client, and cron running against it.

Two things are worth pinning here. First the error mapping: whether a failure
is retryable decides whether cron leaves the crash for the next tick or writes
the message into its dump column, and getting that backwards would either spam
thousands of rows with an outage message or reprocess an undecodable artifact
forever. Second the flag: both the in-process and the service paths are in the
tree so the cut-over is one environment variable and is reversible without a
deploy, which only holds if each path is actually reachable.
"""
import json

import pytest
import requests

import helpers
from app import decode_client


class FakeResponse:
    def __init__(self, status_code, payload):
        self.status_code = status_code
        self._payload = payload

    def json(self):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


@pytest.fixture
def service(monkeypatch):
    """Point the client at a fake service and capture what it sends."""
    monkeypatch.setenv("DECODE_SERVICE_URL", "http://gdb.internal:8002")
    monkeypatch.setenv("DECODE_SERVICE_TOKEN", "tok")
    sent = {}

    def _respond(response):
        def post(url, json=None, headers=None, timeout=None):
            sent.update(url=url, body=json, headers=headers, timeout=timeout)
            if isinstance(response, Exception):
                raise response
            return response
        monkeypatch.setattr(requests, "post", post)
        return sent

    return _respond


# --------------------------------------------------------------- the client

def test_configured_follows_the_environment(monkeypatch):
    monkeypatch.delenv("DECODE_SERVICE_URL", raising=False)
    assert decode_client.configured() is False
    monkeypatch.setenv("DECODE_SERVICE_URL", "http://x")
    assert decode_client.configured() is True


def test_a_successful_decode_returns_the_service_result(service):
    sent = service(FakeResponse(200, {"report": "text", "modules": [], "module_names": []}))
    result = decode_client.decode_crash(42)
    assert result["report"] == "text"
    assert sent["url"].endswith("/v1/decode")
    assert sent["body"] == {"crash_id": 42}
    assert sent["headers"]["Authorization"] == "Bearer tok"


def test_a_specific_build_can_be_requested(service):
    sent = service(FakeResponse(200, {"report": "", "modules": [], "module_names": []}))
    decode_client.decode_crash(42, elf_file_id=7)
    assert sent["body"] == {"crash_id": 42, "elf_file_id": 7}


def test_a_retryable_error_becomes_unavailable(service):
    service(FakeResponse(422, {"error": {"code": "no_build", "message": "no build yet",
                                          "retryable": True}}))
    with pytest.raises(decode_client.DecodeUnavailable, match="no build yet"):
        decode_client.decode_crash(1)


def test_a_permanent_error_becomes_permanent(service):
    service(FakeResponse(422, {"error": {"code": "convert_failed", "message": "garbage",
                                          "retryable": False}}))
    with pytest.raises(decode_client.DecodePermanent, match="garbage"):
        decode_client.decode_crash(1)


def test_an_unreachable_service_is_transient(service):
    service(requests.exceptions.ConnectionError("refused"))
    with pytest.raises(decode_client.DecodeUnavailable, match="unreachable"):
        decode_client.decode_crash(1)


def test_an_unparseable_response_is_transient(service):
    """A response we cannot make sense of says nothing about the crash, so it
    must not be recorded against it."""
    service(FakeResponse(502, ValueError("not json")))
    with pytest.raises(decode_client.DecodeUnavailable, match="HTTP 502"):
        decode_client.decode_crash(1)


def test_missing_configuration_is_transient(monkeypatch):
    monkeypatch.delenv("DECODE_SERVICE_URL", raising=False)
    with pytest.raises(decode_client.DecodeUnavailable):
        decode_client.decode_crash(1)


# ------------------------------------------------------------ cron using it

# compute_signature drops the frames present on every crash regardless of
# cause (panic_abort, esp_system_abort, abort, vPortTaskWrapper), so a report
# needs at least one distinctive frame to be fingerprintable.
REPORT = (
    "CURRENT THREAD STACK =====\n"
    "#0  panic_abort (details=0x1 \"boom\") at panic.c:1\n"
    "#1  0x4008 in watchdog_timer_isr_callback (timer=0x2) at watchdog.c:335\n"
    "#2  0x4009 in gptimer_default_isr (args=0x3) at gptimer.c:470\n"
)
MODULES = [{"name": "modA", "version": "1", "sha1": "b" * 40,
            "text": 0x4000, "data": 0x3ff0, "bss": 0x3ff8, "rodata": 0x3f40,
            "symbols": True}]


@pytest.fixture
def pending(db_conn):
    helpers.create_project(db_conn, "proj-cron-svc", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-cron-svc")
    helpers.create_elf_file(db_conn, "proj-cron-svc", "1.0")
    return helpers.create_crash(db_conn, "proj-cron-svc", "1.0", device_id)


def stored(db_conn, crash_id):
    with db_conn.cursor() as cur:
        cur.execute("SELECT dump, module_names, module_map, signature "
                    "FROM crash WHERE crash_id = %s", (crash_id,))
        return cur.fetchone()


def test_cron_stores_what_the_service_returns(app, db_conn, pending, monkeypatch):
    monkeypatch.setenv("DECODE_SERVICE_URL", "http://gdb.internal:8002")
    monkeypatch.setattr(decode_client, "decode_crash",
                        lambda crash_id, **kw: {
                            "report": REPORT, "modules": MODULES,
                            "module_names": ["modA"], "toolchain": "xtensa-esp32",
                            "toolchain_source": "project", "elf_file_id": 1,
                            "elf_count": 1})
    from app.routes.cron import cron
    with app.app_context():
        cron()

    dump, names, module_map, signature = stored(db_conn, pending)
    assert dump == REPORT
    assert names == ["modA"]
    # Section addresses must survive into module_map, or the zip download
    # cannot emit symbol-loading commands.
    assert module_map[0]["text"] == 0x4000 and module_map[0]["rodata"] == 0x3f40
    assert signature, "a parseable backtrace must yield a signature"


def test_cron_leaves_the_row_alone_when_the_service_is_unavailable(
        app, db_conn, pending, monkeypatch):
    """Storing anything here would mark the crash processed when the real
    problem was an outage - and it would never be retried."""
    monkeypatch.setenv("DECODE_SERVICE_URL", "http://gdb.internal:8002")

    def unavailable(crash_id, **kw):
        raise decode_client.DecodeUnavailable("service down")

    monkeypatch.setattr(decode_client, "decode_crash", unavailable)
    from app.routes.cron import cron
    with app.app_context():
        cron()

    dump, _names, _map, _sig = stored(db_conn, pending)
    assert dump is None, "the crash must remain pending for the next tick"


def test_cron_records_a_permanent_failure_so_it_stops_requeueing(
        app, db_conn, pending, monkeypatch):
    monkeypatch.setenv("DECODE_SERVICE_URL", "http://gdb.internal:8002")

    def permanent(crash_id, **kw):
        raise decode_client.DecodePermanent("this dump is truncated")

    monkeypatch.setattr(decode_client, "decode_crash", permanent)
    from app.routes.cron import cron
    with app.app_context():
        cron()

    dump, _names, module_map, _sig = stored(db_conn, pending)
    assert dump == "this dump is truncated"
    assert module_map == []


def test_cron_stops_when_the_tick_budget_is_spent(app, db_conn, monkeypatch):
    """The signature backfill and AI passes run after the decode loop, so a
    backlog of slow decodes must not starve them."""
    helpers.create_project(db_conn, "proj-budget", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-budget")
    helpers.create_elf_file(db_conn, "proj-budget", "1.0")
    for _ in range(4):
        helpers.create_crash(db_conn, "proj-budget", "1.0", device_id)

    monkeypatch.setenv("DECODE_SERVICE_URL", "http://gdb.internal:8002")
    monkeypatch.setenv("DECODE_TICK_BUDGET_SECONDS", "0")
    calls = []
    monkeypatch.setattr(decode_client, "decode_crash",
                        lambda crash_id, **kw: calls.append(crash_id) or {
                            "report": REPORT, "modules": [], "module_names": [],
                            "toolchain": "t", "toolchain_source": "default",
                            "elf_file_id": 1, "elf_count": 1})
    from app.routes.cron import cron
    with app.app_context():
        cron()
    assert len(calls) <= 1, "a spent budget must stop the loop, not run it dry"
