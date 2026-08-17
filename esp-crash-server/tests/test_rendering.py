"""Tests for app/rendering.py's external_url_for - specifically that it
works with only an app context active and no request context, which is how
cron_runner.py's direct (non-HTTP) calls into cron() run. Regression test
for "RuntimeError: Unable to build URLs outside an active request without
'SERVER_NAME' configured", seen in production after the cron-local-runner
refactor moved cron() off the HTTP request path that used to supply one."""
import helpers
from app.rendering import TAG_COLORS, external_url_for, tag_color


def test_external_url_for_works_without_a_request_context(app, monkeypatch):
    monkeypatch.setitem(app.config, "EXTERNAL_URL", "https://esp-crash.example")
    with app.app_context():
        url = external_url_for("show_project_crash", project_name="proj-a", crash_id=123)
    assert url == "https://esp-crash.example/projects/proj-a/123"


def test_external_url_for_falls_back_to_url_for_external_true(app, monkeypatch):
    """No EXTERNAL_URL configured - falls back to url_for(..., _external=True),
    which also needs a request context to build anything."""
    monkeypatch.setitem(app.config, "EXTERNAL_URL", "")
    with app.app_context():
        url = external_url_for("show_project_crash", project_name="proj-a", crash_id=123)
    assert url.startswith("http")
    assert url.endswith("/projects/proj-a/123")


def test_cron_webhook_notification_survives_without_a_request_context(app, db_conn, monkeypatch):
    """End-to-end regression check: a cron tick that sends a webhook (which
    calls external_url_for) must not fail when run the way cron_runner.py
    runs it - inside only an app context, no request."""
    import requests
    from app import decode
    from app.routes.cron import cron

    monkeypatch.setitem(app.config, "EXTERNAL_URL", "https://esp-crash.example")

    def fake_resolve(dump_path, prog_path):
        import os
        import tempfile
        fd, core_elf = tempfile.mkstemp()
        os.close(fd)
        return ([], [], "base panic text\n", core_elf, [])

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", fake_resolve)

    calls = []

    class FakeResponse:
        def raise_for_status(self):
            pass

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append((url, json))
        return FakeResponse()

    monkeypatch.setattr(requests, "post", fake_post)

    device_id = helpers.create_device(db_conn, "dev-cron-render-regress")
    helpers.create_elf_file(db_conn, "proj-cron-render-regress", "1.0")
    helpers.create_crash(db_conn, "proj-cron-render-regress", "1.0", device_id, crash_dmp=b"raw-dump")
    helpers.create_webhook(db_conn, "proj-cron-render-regress", "https://hooks.test/notify")

    with app.app_context():
        result = cron()  # must not raise

    assert result == ("OK\n", 200)
    assert len(calls) == 1
    assert calls[0][1]["details_url"].startswith("https://esp-crash.example/")


def test_tag_color_is_stable_and_case_insensitive():
    """A tag's dot colour must not move between requests, workers or restarts,
    which is why tag_color hashes with md5 rather than the salted built-in
    hash(). Same name (any casing/padding) -> same colour, always."""
    assert tag_color("watchdog") == tag_color("watchdog")
    assert tag_color("Backend") == tag_color("backend") == tag_color(" BACKEND ")
    assert tag_color("watchdog") in TAG_COLORS
    assert tag_color(None) in TAG_COLORS  # no name at all still yields a colour


def test_tag_color_spreads_names_over_the_palette():
    """Distinct tags should mostly get distinct colours - not a guarantee (the
    palette is finite, so collisions are expected), but a single-colour result
    would mean the hash is not being used."""
    names = ["watchdog", "ota", "mqtt", "abort", "backend", "integration-goodwe", "wifi", "heap"]
    assert len({tag_color(n) for n in names}) >= 5
