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
    assert crash["ai_summary"] is None
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


def test_set_build_alias_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    build_id = helpers.create_elf_file(db_conn, "proj-a", "1.0", project_alias="old")

    # other user can't rename it
    result = tools.set_build_alias("mallory", build_id, "new-alias")
    assert result["updated"] is False
    with db_conn.cursor() as cur:
        cur.execute("SELECT project_alias FROM elf_file WHERE elf_file_id = %s", (build_id,))
        assert cur.fetchone()[0] == "old"

    # owner can
    result = tools.set_build_alias("alice", build_id, "new-alias")
    assert result["updated"] is True
    with db_conn.cursor() as cur:
        cur.execute("SELECT project_alias FROM elf_file WHERE elf_file_id = %s", (build_id,))
        assert cur.fetchone()[0] == "new-alias"


def test_set_device_alias_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1", alias="old")
    helpers.create_crash(db_conn, "proj-a", "1.0", dev)

    # other user can't rename it
    result = tools.set_device_alias("mallory", dev, "thermostat")
    assert result["updated"] is False
    with db_conn.cursor() as cur:
        cur.execute("SELECT alias FROM device WHERE device_id = %s", (dev,))
        assert cur.fetchone()[0] == "old"

    # owner can, via a crash under their project
    result = tools.set_device_alias("alice", dev, "thermostat")
    assert result["updated"] is True
    with db_conn.cursor() as cur:
        cur.execute("SELECT alias FROM device WHERE device_id = %s", (dev,))
        assert cur.fetchone()[0] == "thermostat"


def test_set_device_alias_denied_for_device_with_no_accessible_crash(app, db_conn, ctx):
    dev = helpers.create_device(db_conn, "dev-1")

    result = tools.set_device_alias("alice", dev, "thermostat")
    assert result["updated"] is False


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


def test_list_tags_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    helpers.create_project(db_conn, "proj-b", github_user="bob")
    helpers.create_tag(db_conn, "proj-a", "reviewed", description="Looked at")
    helpers.create_tag(db_conn, "proj-b", "wontfix")

    alice = tools.list_tags("alice", "proj-a")
    assert [t["name"] for t in alice] == ["reviewed"]
    assert alice[0]["description"] == "Looked at"
    # can't see another user's project's tags
    assert tools.list_tags("alice", "proj-b") == []


def test_add_tag_to_crash_creates_and_reuses(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    sig = "d" * 64
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig)

    result = tools.add_tag_to_crash("alice", crash_id, "Reviewed", "Looked at")
    assert result["added"] is True
    assert result["tag"]["name"] == "reviewed"  # case-folded

    # re-adding the same (case-insensitive) name reuses the tag_id, doesn't error
    result2 = tools.add_tag_to_crash("alice", crash_id, "REVIEWED")
    assert result2["tag"]["tag_id"] == result["tag"]["tag_id"]

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM crash_relation_tag WHERE project_name = %s AND signature = %s",
            ("proj-a", sig),
        )
        assert cur.fetchone()[0] == 1


def test_add_tag_to_crash_denied_for_other_user(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature="e" * 64)

    result = tools.add_tag_to_crash("mallory", crash_id, "wontfix")
    assert result["added"] is False
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM tag")
        assert cur.fetchone()[0] == 0


def test_add_tag_to_crash_rejects_unsignatured_crash(app, db_conn, ctx):
    """Tags live on the crash's relation (project_name, signature) - a
    crash with no signature has no relation to attach one to."""
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev)

    result = tools.add_tag_to_crash("alice", crash_id, "wontfix")
    assert result["added"] is False
    assert result["reason"] == "crash has no signature"


def test_tag_name_scoped_per_project(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    helpers.create_project(db_conn, "proj-b", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_a = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature="f" * 64)
    crash_b = helpers.create_crash(db_conn, "proj-b", "1.0", dev, signature="f" * 64)

    tag_a = tools.add_tag_to_crash("alice", crash_a, "wontfix")["tag"]
    tag_b = tools.add_tag_to_crash("alice", crash_b, "wontfix")["tag"]
    assert tag_a["tag_id"] != tag_b["tag_id"]


def test_remove_tag_from_crash(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    sig = "g" * 64
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig)
    tag_id = tools.add_tag_to_crash("alice", crash_id, "wontfix")["tag"]["tag_id"]

    # other user can't remove it
    assert tools.remove_tag_from_crash("mallory", crash_id, tag_id)["removed"] is False

    assert tools.remove_tag_from_crash("alice", crash_id, tag_id)["removed"] is True
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM crash_relation_tag WHERE project_name = %s AND signature = %s",
            ("proj-a", sig),
        )
        assert cur.fetchone()[0] == 0
    # the tag itself is left intact for reuse
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM tag WHERE tag_id = %s", (tag_id,))
        assert cur.fetchone()[0] == 1


def test_list_crashes_tag_filter(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_1 = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature="h" * 64)
    crash_2 = helpers.create_crash(db_conn, "proj-a", "1.0", dev)
    tag_id = helpers.create_tag(db_conn, "proj-a", "wontfix")
    helpers.tag_crash(db_conn, crash_1, tag_id)

    filtered = tools.list_crashes("alice", tag_id=tag_id)
    assert [c["crash_id"] for c in filtered] == [crash_1]
    assert filtered[0]["tags"][0]["name"] == "wontfix"

    unfiltered = tools.list_crashes("alice")
    assert {c["crash_id"] for c in unfiltered} == {crash_1, crash_2}


def test_list_crashes_signature_filter(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    sig = "a" * 64
    crash_1 = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig)
    crash_2 = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig)
    helpers.create_crash(db_conn, "proj-a", "1.0", dev)  # different signature (none) - must not match

    filtered = tools.list_crashes("alice", signature=sig)
    assert {c["crash_id"] for c in filtered} == {crash_1, crash_2}
    assert all(c["signature"] == sig for c in filtered)


def test_list_crashes_signature_filter_scoped_to_caller(app, db_conn, ctx):
    """The signature filter must still respect project ACLs - it's not a
    backdoor around list_crashes's normal scoping."""
    sig = "b" * 64
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev_a = helpers.create_device(db_conn, "dev-a")
    helpers.create_crash(db_conn, "proj-a", "1.0", dev_a, signature=sig)

    helpers.create_project(db_conn, "proj-b", github_user="bob")
    dev_b = helpers.create_device(db_conn, "dev-b")
    helpers.create_crash(db_conn, "proj-b", "1.0", dev_b, signature=sig)

    alice_view = tools.list_crashes("alice", signature=sig)
    assert [c["project_name"] for c in alice_view] == ["proj-a"]


def test_get_crash_includes_signature(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    sig = "c" * 64
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig)

    crash = tools.get_crash("alice", crash_id)
    assert crash["signature"] == sig


def test_get_crash_includes_tags(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature="i" * 64)
    tag_id = helpers.create_tag(db_conn, "proj-a", "reviewed", description="Looked at")
    helpers.tag_crash(db_conn, crash_id, tag_id)

    crash = tools.get_crash("alice", crash_id)
    assert crash["tags"] == [{"tag_id": tag_id, "name": "reviewed", "description": "Looked at"}]


def test_delete_crash_does_not_remove_relation_tags(app, db_conn, ctx):
    """Tags are owned by the relation (project_name, signature), not the
    crash - deleting one crash must not touch tags that could still apply
    to other crashes sharing the same signature (crash_relation_tag has no
    FK to crash at all)."""
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    sig = "j" * 64
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig)
    tag_id = helpers.create_tag(db_conn, "proj-a", "wontfix")
    helpers.tag_crash(db_conn, crash_id, tag_id)

    assert tools.delete_crash("alice", crash_id)["deleted"] == 1
    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM crash_relation_tag WHERE project_name = %s AND signature = %s",
            ("proj-a", sig),
        )
        assert cur.fetchone()[0] == 1
    # the tag row itself survives too (orphaned tags are kept for reuse)
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM tag WHERE tag_id = %s", (tag_id,))
        assert cur.fetchone()[0] == 1


def test_add_tag_to_crash_includes_relation_key(app, db_conn, ctx):
    """The tag fan-out (tags belong to (project_name, signature), not
    crash_id) must be explicit in the response, not just implicit DB
    behavior - see mcp_app/tools.py:add_tag_to_crash."""
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    sig = "k" * 64
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig)

    result = tools.add_tag_to_crash("alice", crash_id, "wontfix")
    assert result["project_name"] == "proj-a"
    assert result["signature"] == sig

    remove_result = tools.remove_tag_from_crash("alice", crash_id, result["tag"]["tag_id"])
    assert remove_result["project_name"] == "proj-a"
    assert remove_result["signature"] == sig


def test_reload_crash_summary_clears_for_whole_group(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    sig = "l" * 64
    crash_1 = helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig, ai_title="Old title", ai_summary="Old summary")
    helpers.create_crash(db_conn, "proj-a", "1.1", dev, signature=sig)

    result = tools.reload_crash_summary("alice", crash_1)
    assert result["reloaded"] is True

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_title, ai_summary FROM crash_relation WHERE project_name = %s AND signature = %s", ("proj-a", sig))
        assert cur.fetchone() == (None, None)


def test_reload_crash_summary_noop_without_signature_or_access(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-a", "1.0", dev)

    assert tools.reload_crash_summary("alice", crash_id)["reloaded"] is False
    assert tools.reload_crash_summary("mallory", crash_id)["reloaded"] is False


def test_list_relations_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    helpers.create_project(db_conn, "proj-b", github_user="bob")
    dev = helpers.create_device(db_conn, "dev-1")
    sig_a = "m" * 64
    helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig_a, ai_title="Bug A")
    helpers.create_crash(db_conn, "proj-a", "1.0", dev, signature=sig_a)
    sig_b = "n" * 64
    helpers.create_crash(db_conn, "proj-b", "1.0", dev, signature=sig_b)

    result = tools.list_relations("alice", "proj-a")
    assert result["full_count"] == 1
    assert [r["signature"] for r in result["items"]] == [sig_a]
    assert result["items"][0]["crash_count"] == 2
    assert result["items"][0]["ai_title"] == "Bug A"

    # bob's project is invisible to alice even when named directly
    assert tools.list_relations("alice", "proj-b")["items"] == []


def test_acl_list_add_remove(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")

    assert tools.list_acl("mallory", "proj-a") is None

    acl = tools.list_acl("alice", "proj-a")
    assert [a["github"] for a in acl] == ["alice"]

    assert tools.add_acl("mallory", "proj-a", "carol")["added"] is False
    added = tools.add_acl("alice", "proj-a", "carol")
    assert added["added"] is True
    assert tools.add_acl("alice", "proj-a", "carol")["reason"] == "already exists"

    assert tools.remove_acl("mallory", "proj-a", "carol")["removed"] is False
    assert tools.remove_acl("alice", "proj-a", "carol")["removed"] is True
    assert [a["github"] for a in tools.list_acl("alice", "proj-a")] == ["alice"]


def test_webhooks_list_add_remove(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")

    assert tools.list_webhooks("mallory", "proj-a") is None
    assert tools.list_webhooks("alice", "proj-a") == []

    added = tools.add_webhook("alice", "proj-a", "https://example.com/hook")
    assert added["added"] is True
    assert tools.add_webhook("alice", "proj-a", "https://example.com/hook")["reason"] == "already exists"
    assert tools.add_webhook("mallory", "proj-a", "https://evil.example/hook")["added"] is False

    webhooks = tools.list_webhooks("alice", "proj-a")
    assert [w["webhook_url"] for w in webhooks] == ["https://example.com/hook"]

    assert tools.remove_webhook("mallory", "proj-a", added["webhook_id"])["removed"] is False
    assert tools.remove_webhook("alice", "proj-a", added["webhook_id"])["removed"] is True
    assert tools.list_webhooks("alice", "proj-a") == []


def test_device_url_template_get_set_validates(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")

    assert tools.get_device_url_template("mallory", "proj-a") is None
    assert tools.get_device_url_template("alice", "proj-a")["device_url_template"] is None

    bad = tools.set_device_url_template("alice", "proj-a", "not-a-url")
    assert bad["updated"] is False
    assert bad["reason"] == "invalid_template"

    good = tools.set_device_url_template("alice", "proj-a", "https://iot.example/{device_id}")
    assert good["updated"] is True
    assert tools.get_device_url_template("alice", "proj-a")["device_url_template"] == "https://iot.example/{device_id}"

    # blank clears it
    cleared = tools.set_device_url_template("alice", "proj-a", "")
    assert cleared["updated"] is True
    assert tools.get_device_url_template("alice", "proj-a")["device_url_template"] is None

    assert tools.set_device_url_template("mallory", "proj-a", "https://x/{device_id}")["updated"] is False


def test_get_project_settings_composite(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    helpers.create_webhook(db_conn, "proj-a", "https://example.com/hook")
    helpers.create_slack_integration(db_conn, "proj-a")
    tools.set_device_url_template("alice", "proj-a", "https://iot.example/{device_id}")

    assert tools.get_project_settings("mallory", "proj-a") is None

    settings = tools.get_project_settings("alice", "proj-a")
    assert [a["github"] for a in settings["acl"]] == ["alice"]
    assert len(settings["webhooks"]) == 1
    assert len(settings["slack_integrations"]) == 1
    assert "slack_access_token" not in settings["slack_integrations"][0]
    assert settings["device_url_template"] == "https://iot.example/{device_id}"


def test_get_device_scoped(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    dev = helpers.create_device(db_conn, "dev-1", alias="thermostat")
    helpers.create_crash(db_conn, "proj-a", "1.0", dev)

    assert tools.get_device("mallory", dev) is None
    device = tools.get_device("alice", dev)
    assert device["ext_device_id"] == "dev-1"
    assert device["alias"] == "thermostat"


def test_slack_integrations_list_remove_set_channel(app, db_conn, ctx):
    helpers.create_project(db_conn, "proj-a", github_user="alice")
    integration_id = helpers.create_slack_integration(db_conn, "proj-a", slack_channel_name="general")

    assert tools.list_slack_integrations("mallory", "proj-a") is None
    integrations = tools.list_slack_integrations("alice", "proj-a")
    assert [i["slack_channel_name"] for i in integrations] == ["general"]

    updated = tools.set_slack_channel("alice", "proj-a", integration_id, "C999", "random")
    assert updated["updated"] is True
    assert tools.list_slack_integrations("alice", "proj-a")[0]["slack_channel_name"] == "random"

    assert tools.set_slack_channel("mallory", "proj-a", integration_id, "C111", "other")["updated"] is False

    assert tools.remove_slack_integration("mallory", "proj-a", integration_id)["removed"] is False
    assert tools.remove_slack_integration("alice", "proj-a", integration_id)["removed"] is True
    assert tools.list_slack_integrations("alice", "proj-a") == []
