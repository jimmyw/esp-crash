"""Standalone process behind the `cron` docker-compose service.

Historically this container just looped `curl backend:8000/cron` every 10s,
meaning app/routes/cron.py's actual logic ran inside the `backend` gunicorn
workers and its log lines showed up under backend's log stream. This calls
app.routes.cron.cron() directly instead - no HTTP round trip, no dependency
on `backend` being reachable, and cron's own log lines now show up under
this process's own stdout/stderr (captured by the `cron` service's own
logging driver - see docker-compose.yml), using the exact same
logging.basicConfig() setup as the web app (app.create_app()) so the format
is identical.

Run with: python cron_runner.py

Logs via app.logger (current_app.logger inside the app context), same as
every other module in this codebase (app/routes/cron.py included) - not a
module-level logging.getLogger(__name__) - so it's created lazily the same
way and picked up by the same logging.basicConfig() setup from
app.create_app(), rather than as a standalone logger that could exist
before that setup runs.
"""
import os
import time

from app import create_app
from app.routes.cron import cron as run_cron

INTERVAL_SECONDS = int(os.environ.get("CRON_INTERVAL_SECONDS", "10"))


def _tick(app):
    """Run one cron pass inside a fresh app context. Exceptions are caught
    and logged, not raised - a single bad tick (e.g. a transient DB hiccup)
    must not take the whole process down, and the next tick just retries.
    Exiting the `with` block runs Flask-SQLAlchemy's teardown handler
    (db.session.remove()) whether or not the tick raised, so a failed tick
    can't leave a dangling transaction for the next one - the same
    guarantee a normal HTTP request gets."""
    with app.app_context():
        try:
            run_cron()
        except Exception:
            app.logger.exception("cron tick failed")


def main():
    app = create_app()
    app.logger.info("cron runner starting (interval=%ss)", INTERVAL_SECONDS)
    while True:
        time.sleep(INTERVAL_SECONDS)
        _tick(app)


if __name__ == "__main__":
    main()
