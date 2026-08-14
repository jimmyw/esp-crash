"""Tests for cron_runner.py - the standalone process behind the `cron`
docker-compose service (calls app.routes.cron.cron() directly instead of
looping `curl backend:8000/cron`). Most tests here monkeypatch run_cron so
they don't duplicate app/routes/cron.py's own tests (tests/test_cron.py) -
one end-to-end test below exercises the real, unmocked path."""
import logging
import os
import tempfile

import cron_runner
import helpers


def test_tick_processes_a_real_pending_crash_end_to_end(app, db_conn, monkeypatch):
    """No mocking of run_cron - proves _tick actually drives the real
    app.routes.cron.cron() logic against the DB, the same as the old
    `curl backend:8000/cron` path did."""
    from app import decode

    def fake_resolve(dump_path, prog_path):
        fd, core_elf = tempfile.mkstemp()
        os.close(fd)
        return ([], [], "base panic text\n", core_elf, [])

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", fake_resolve)

    device_id = helpers.create_device(db_conn, "dev-cron-runner-e2e")
    helpers.create_elf_file(db_conn, "proj-cron-runner-e2e", "1.0")
    crash_id = helpers.create_crash(
        db_conn, "proj-cron-runner-e2e", "1.0", device_id, crash_dmp=b"raw-dump",
    )

    cron_runner._tick(app)

    with db_conn.cursor() as cur:
        cur.execute("SELECT dump FROM crash WHERE crash_id = %s", (crash_id,))
        assert "base panic text" in cur.fetchone()[0]


def test_tick_runs_cron_inside_an_app_context(app, monkeypatch):
    from flask import current_app

    calls = []

    def fake_cron():
        calls.append(current_app.name)
        return "OK\n", 200

    monkeypatch.setattr(cron_runner, "run_cron", fake_cron)
    cron_runner._tick(app)

    assert calls == [app.name]


def test_tick_catches_and_logs_exceptions_without_raising(app, monkeypatch, caplog):
    def boom():
        raise RuntimeError("db exploded")

    monkeypatch.setattr(cron_runner, "run_cron", boom)

    with caplog.at_level(logging.ERROR, logger=app.logger.name):
        cron_runner._tick(app)  # must not raise

    assert "cron tick failed" in caplog.text


def test_tick_failure_does_not_leave_a_dangling_session(app, monkeypatch):
    """A failed tick must still tear down the app context (and with it,
    Flask-SQLAlchemy's db.session.remove()) so the next tick starts clean -
    same guarantee a normal HTTP request gets on exception."""
    from app.models import db

    def boom():
        # Touch the session before blowing up, like a real query would.
        db.session.execute(db.text("SELECT 1"))
        raise RuntimeError("boom")

    monkeypatch.setattr(cron_runner, "run_cron", boom)
    cron_runner._tick(app)

    with app.app_context():
        assert not db.session.registry.has()
