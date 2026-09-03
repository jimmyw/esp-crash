"""POST /v1/decode: authentication, error taxonomy, and route exposure.

The exposure tests matter as much as the auth ones. This endpoint performs an
*unscoped* read - any crash, any project - so where it is reachable from is part
of its security, not a detail. `gdb_app/server.py:routes_at` registers every
session route both bare and under `GDB_PATH_PREFIX`, and the reverse proxy
forwards the prefixed path from the public internet; a test therefore pins that
this route is not among them.
"""
import bz2
import os

import pytest
from starlette.testclient import TestClient

import helpers

TOKEN = "test-decode-service-token"


@pytest.fixture
def build(server_module, monkeypatch):
    """Build the debug service's ASGI app with a chosen environment."""
    from gdb_app import server as gdb_server

    def _build(token=TOKEN, prefix=None, batch_slots=None):
        monkeypatch.setenv("GDB_TICKET_SECRET", "irrelevant-here")
        if token is None:
            monkeypatch.delenv("DECODE_SERVICE_TOKEN", raising=False)
        else:
            monkeypatch.setenv("DECODE_SERVICE_TOKEN", token)
        if prefix is None:
            monkeypatch.delenv("GDB_PATH_PREFIX", raising=False)
        else:
            monkeypatch.setenv("GDB_PATH_PREFIX", prefix)
        if batch_slots is not None:
            monkeypatch.setenv("GDB_BATCH_SLOTS", str(batch_slots))
        return TestClient(gdb_server.build_app())

    return _build


def seed(db_conn, *, dump=b"not-a-real-coredump", with_build=True,
         project="proj", ver="1.0"):
    helpers.create_project(db_conn, project, github_user="alice")
    device_id = helpers.create_device(db_conn, f"dev-{project}")
    if with_build:
        helpers.create_elf_file(db_conn, project, ver, elf_bytes=b"ELF")
    with db_conn.cursor() as cur:
        cur.execute("INSERT INTO project_settings (project_name, toolchain) "
                    "VALUES (%s, %s)", (project, "xtensa-esp32"))
    return helpers.create_crash(db_conn, project, ver, device_id,
                                crash_dmp=bz2.compress(dump) if dump else None)


@pytest.fixture
def needs_toolchain():
    """Skip when no toolchain package is mounted.

    Reaching a `no_build` or `convert_failed` outcome means getting *past*
    toolchain resolution, so these two need a real installed toolchain -
    without one the endpoint correctly reports `no_toolchain` instead. Same
    convention as the integration tests: say why rather than depend on how the
    suite happened to be invoked.
    """
    import toolchains
    if not toolchains.installed():
        pytest.skip("no toolchain package mounted at /opt/toolchains")


def post(client, payload, token=TOKEN):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/v1/decode", json=payload, headers=headers)


# ------------------------------------------------------------ authentication

def test_a_token_is_required(build, db_conn):
    crash_id = seed(db_conn)
    assert post(build(), {"crash_id": crash_id}, token=None).status_code == 401


def test_a_wrong_token_is_refused(build, db_conn):
    crash_id = seed(db_conn)
    r = post(build(), {"crash_id": crash_id}, token="not-the-token")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "unauthorized"


def test_a_token_that_is_a_prefix_of_the_real_one_is_refused(build, db_conn):
    """Compared with hmac.compare_digest, so a partial match is no closer than
    any other wrong value."""
    crash_id = seed(db_conn)
    assert post(build(), {"crash_id": crash_id}, token=TOKEN[:-1]).status_code == 401


# --------------------------------------------------------------- route exposure

def test_the_route_does_not_exist_without_a_token(build, db_conn):
    """A deployment that has not opted in should present no surface at all,
    rather than one that answers 401."""
    crash_id = seed(db_conn)
    assert post(build(token=None), {"crash_id": crash_id}).status_code == 404


def test_the_route_is_not_served_under_the_public_path_prefix(build, db_conn):
    """The prefixed paths are what the reverse proxy forwards from the
    internet. An unscoped all-projects crash read must not be among them."""
    crash_id = seed(db_conn)
    client = build(prefix="/gdb")
    # The session routes are served both ways...
    assert client.get("/gdb/health").status_code == 200
    assert client.get("/health").status_code == 200
    # ...but decode only unprefixed.
    assert post(client, {"crash_id": crash_id}).status_code != 404
    assert client.post("/gdb/v1/decode", json={"crash_id": crash_id},
                       headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 404


# ------------------------------------------------------------------ requests

@pytest.mark.parametrize("payload", [{}, {"crash_id": "abc"}, {"nope": 1}])
def test_a_malformed_body_is_a_400(build, payload):
    assert post(build(), payload).status_code == 400


def test_an_unknown_crash_is_a_permanent_404(build):
    r = post(build(), {"crash_id": 987654321})
    assert r.status_code == 404
    assert r.json()["error"] == {"code": "not_found",
                                 "message": "No crash with id 987654321.",
                                 "retryable": False}


def test_a_crash_with_no_build_is_retryable(build, db_conn, needs_toolchain):
    """A build may still be uploaded, so the crash must be left alone rather
    than marked undecodable."""
    crash_id = seed(db_conn, with_build=False)
    r = post(build(), {"crash_id": crash_id})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "no_build"
    assert r.json()["error"]["retryable"] is True


def test_an_undecodable_artifact_is_permanent(build, db_conn, needs_toolchain):
    """Garbage will not become decodable on the next tick, and retrying it
    forever would consume the batch budget that real crashes need."""
    crash_id = seed(db_conn, dump=b"definitely not a coredump")
    r = post(build(), {"crash_id": crash_id})
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "convert_failed"
    assert r.json()["error"]["retryable"] is False


# ------------------------------------------------------------- pool partition

def test_the_batch_pool_is_disjoint_from_the_interactive_one(build):
    """Partitioned rather than shared: a semaphore over one pool would still
    let batch work take the last slot an interactive user is waiting for."""
    info = build(batch_slots=4).get("/v1/info").json()
    assert info["batch_capacity"] == 4
    assert info["capacity"] >= 1
    assert info["capacity"] + info["batch_capacity"] == len(_accounts())
    assert info["decode"] is True


def test_info_reports_decode_disabled_when_no_token(build):
    assert build(token=None).get("/v1/info").json()["decode"] is False


def _accounts():
    from gdb_app.uidpool import discover_accounts
    return discover_accounts()
