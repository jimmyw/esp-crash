"""Tests for the MCP tool logic (mcp_app/tools.py) - exercised directly with
an explicit github_user inside a Flask app context, so no OAuth/transport
layer is needed. Focus: correct results, action DB-state effects, and that
ACL scoping hides another user's data."""
import pytest

import helpers
from mcp_app import tools


@pytest.fixture
def ctx(app):
    """Run tool calls inside a Flask app context so app.models.db.session works."""
    with app.app_context():
        yield


def test_list_projects_scoped_to_user(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    helpers.create_project(db_conn, "proj-b", github_user="bob")

    alice = [p["project_name"] for p in tools.list_projects("alice")]
    bob = [p["project_name"] for p in tools.list_projects("bob")]

    assert alice == ["proj-a"]
    assert bob == ["proj-b"]


def test_list_projects_includes_crash_count(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    helpers.create_crash(db_conn, "proj-a", "1.0", dev)
    helpers.create_crash(db_conn, "proj-a", "1.0", dev)

    projects = tools.list_projects("alice")
    assert projects[0]["crash_count"] == 2


def test_list_crashes_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    helpers.create_project(db_conn, "proj-b", github_user="bob")
    dev = helpers.create_device(db_conn, "dev-1", alias="thermostat")
    helpers.create_crash(db_conn, "proj-a", "1.0", dev)
    helpers.create_crash(db_conn, "proj-b", "2.0", dev)

    alice = tools.list_crashes("alice")
    assert [c["project_name"] for c in alice] == ["proj-a"]
    assert alice[0]["ext_device_id"] == "dev-1"
    assert alice[0]["alias"] == "thermostat"
    # bob's crash is invisible to alice
    assert all(c["project_name"] != "proj-b" for c in alice)


def test_list_crashes_project_filter(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    helpers.create_project(db_conn, "proj-b", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    helpers.create_crash(db_conn, "proj-a", "1.0", dev)
    helpers.create_crash(db_conn, "proj-b", "1.0", dev)

    only_a = tools.list_crashes("alice", project_name="proj-a")
    assert [c["project_name"] for c in only_a] == ["proj-a"]


def test_get_crash_returns_dump_and_builds(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, dump="SYMBOLICATED BACKTRACE")
    helpers.create_elf_file(db_conn, "proj-a", "1.0", project_alias="build-x")

    crash = tools.get_crash("alice", crash_id)
    assert crash is not None
    assert crash["dump"] == "SYMBOLICATED BACKTRACE"
    assert crash["ext_device_id"] == "dev-1"
    assert len(crash["builds"]) == 1
    assert crash["builds"][0]["project_alias"] == "build-x"
    # dates serialized to ISO strings (JSON-friendly)
    assert isinstance(crash["date"], str)


def test_get_crash_denied_for_other_user(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev)

    assert tools.get_crash("mallory", crash_id) is None


def test_list_and_get_builds_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    build_id = helpers.create_elf_file(db_conn, "proj-a", "1.0", project_alias="b1")

    builds = tools.list_builds("alice", "proj-a")
    assert [b["elf_file_id"] for b in builds] == [build_id]
    assert tools.get_build("alice", build_id)["project_alias"] == "b1"
    # another user can't fetch it
    assert tools.get_build("mallory", build_id) is None


def test_refresh_crash_clears_dump_when_authorized(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, dump="old dump")

    result = tools.refresh_crash("alice", crash_id)
    assert result["refreshed"] is True

    with db_conn.cursor() as cur:
        cur.execute("SELECT dump FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] is None


def test_refresh_crash_noop_for_other_user(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, dump="keep me")

    result = tools.refresh_crash("mallory", crash_id)
    assert result["refreshed"] is False

    with db_conn.cursor() as cur:
        cur.execute("SELECT dump FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == "keep me"


def test_delete_crash_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev)

    # other user can't delete it
    assert tools.delete_crash("mallory", crash_id)["deleted"] == 0
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == 1

    # owner can
    assert tools.delete_crash("alice", crash_id)["deleted"] == 1
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == 0


def test_delete_build_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    build_id = helpers.create_elf_file(db_conn, "proj-a", "1.0")

    assert tools.delete_build("mallory", build_id)["deleted"] == 0
    assert tools.delete_build("alice", build_id)["deleted"] == 1
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM elf_file WHERE elf_file_id = %s", (build_id,))
        assert cur.fetchone()[0] == 0


def test_create_project(app, db_conn, ctx):
    result = tools.create_project("alice", "new-proj")
    assert result["created"] is True

    with db_conn.cursor() as cur:
        cur.execute("SELECT github FROM project_auth WHERE project_name = %s", ("new-proj",))
        assert cur.fetchone()[0] == "alice"

    # duplicate for same user is rejected
    assert tools.create_project("alice", "new-proj")["created"] is False


def test_create_project_requires_name(app, ctx):
    assert tools.create_project("alice", "")["created"] is False
