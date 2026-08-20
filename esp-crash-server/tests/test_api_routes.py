"""Tests for the /api/v1 JSON API (app/api/*) - the HTTP layer on top of
mcp_app/tools.py. Service-layer correctness/ACL-scoping is already covered
by tests/test_mcp_tools.py; this file focuses on what's specific to the
HTTP surface: status codes, the CSRF header gate, JSON auth responses, and
response envelope shape.

Mutating requests need the X-Api-Client header (see app/api/csrf.py) even
under the AUTH_TYPE=none `client` fixture - CSRF enforcement is orthogonal
to auth mode."""
import helpers

API = "/api/v1"
CSRF = {"X-Api-Client": "1"}


def test_list_projects(client, db_conn):
    helpers.create_project(db_conn, "proj-a", github_user="none")
    resp = client.get(f"{API}/projects")
    assert resp.status_code == 200
    assert [p["project_name"] for p in resp.get_json()] == ["proj-a"]


def test_create_project(client, db_conn):
    resp = client.post(f"{API}/projects", json={"project_name": "new-proj"}, headers=CSRF)
    assert resp.status_code == 201
    assert resp.get_json()["created"] is True

    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM project_auth WHERE project_name = %s", ("new-proj",))
        assert cur.fetchone()[0] == 1


def test_create_project_duplicate_is_conflict(client, db_conn):
    helpers.create_project(db_conn, "dup-proj", github_user="none")
    resp = client.post(f"{API}/projects", json={"project_name": "dup-proj"}, headers=CSRF)
    assert resp.status_code == 409
    assert resp.get_json()["error"]["code"] == "conflict"


def test_create_project_missing_name_is_validation_error(client):
    resp = client.post(f"{API}/projects", json={}, headers=CSRF)
    assert resp.status_code == 422


def test_list_crashes_paginated_envelope(client, db_conn):
    helpers.create_project(db_conn, "proj-b", github_user="none")
    dev = helpers.create_device(db_conn, "dev-1")
    helpers.create_crash(db_conn, "proj-b", "1.0", dev)
    helpers.create_crash(db_conn, "proj-b", "1.0", dev)

    resp = client.get(f"{API}/crashes?limit=1&offset=0")
    assert resp.status_code == 200
    body = resp.get_json()
    assert len(body["items"]) == 1
    assert body["full_count"] == 2
    assert body["limit"] == 1


def test_get_crash_not_found_is_404(client):
    resp = client.get(f"{API}/crashes/999999")
    assert resp.status_code == 404
    assert resp.get_json()["error"]["code"] == "not_found"


def test_get_crash_detail(client, db_conn):
    helpers.create_project(db_conn, "proj-c", github_user="none")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-c", "1.0", dev, dump="symbolicated text")

    resp = client.get(f"{API}/crashes/{crash_id}")
    assert resp.status_code == 200
    assert resp.get_json()["dump"] == "symbolicated text"


def test_delete_crash_requires_csrf_header(client, db_conn):
    helpers.create_project(db_conn, "proj-d", github_user="none")
    dev = helpers.create_device(db_conn, "dev-1")
    crash_id = helpers.create_crash(db_conn, "proj-d", "1.0", dev)

    blocked = client.delete(f"{API}/crashes/{crash_id}")
    assert blocked.status_code == 403
    assert blocked.get_json()["error"]["code"] == "forbidden"
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == 1

    allowed = client.delete(f"{API}/crashes/{crash_id}", headers=CSRF)
    assert allowed.status_code == 200
    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == 0


def test_add_and_remove_crash_tag_fan_out(client, db_conn):
    """Tags belong to the crash's (project_name, signature) relation, not
    crash_id - the response makes that explicit (see
    mcp_app/tools.py:add_tag_to_crash)."""
    helpers.create_project(db_conn, "proj-e", github_user="none")
    dev = helpers.create_device(db_conn, "dev-1")
    sig = "a" * 64
    crash_1 = helpers.create_crash(db_conn, "proj-e", "1.0", dev, signature=sig)
    crash_2 = helpers.create_crash(db_conn, "proj-e", "1.0", dev, signature=sig)

    added = client.post(f"{API}/crashes/{crash_1}/tags", json={"tag_name": "wontfix"}, headers=CSRF)
    assert added.status_code == 201
    body = added.get_json()
    assert body["project_name"] == "proj-e"
    assert body["signature"] == sig
    tag_id = body["tag"]["tag_id"]

    # visible on the other crash sharing the signature too
    other = client.get(f"{API}/crashes/{crash_2}")
    assert [t["tag_id"] for t in other.get_json()["tags"]] == [tag_id]

    removed = client.delete(f"{API}/crashes/{crash_1}/tags/{tag_id}", headers=CSRF)
    assert removed.status_code == 200
    other_after = client.get(f"{API}/crashes/{crash_2}")
    assert other_after.get_json()["tags"] == []


def test_refresh_and_reload_summary_not_found(client):
    assert client.post(f"{API}/crashes/999999/refresh", headers=CSRF).status_code == 404
    assert client.post(f"{API}/crashes/999999/reload-summary", headers=CSRF).status_code == 404


def test_list_and_get_build(client, db_conn):
    helpers.create_project(db_conn, "proj-f", github_user="none")
    build_id = helpers.create_elf_file(db_conn, "proj-f", "1.0", project_alias="b1")

    listed = client.get(f"{API}/projects/proj-f/builds")
    assert listed.status_code == 200
    assert [b["elf_file_id"] for b in listed.get_json()] == [build_id]

    got = client.get(f"{API}/builds/{build_id}")
    assert got.status_code == 200
    assert got.get_json()["project_alias"] == "b1"


def test_set_build_alias(client, db_conn):
    helpers.create_project(db_conn, "proj-g", github_user="none")
    build_id = helpers.create_elf_file(db_conn, "proj-g", "1.0")

    resp = client.patch(f"{API}/builds/{build_id}", json={"alias": "new-alias"}, headers=CSRF)
    assert resp.status_code == 200
    assert resp.get_json()["alias"] == "new-alias"


def test_get_device(client, db_conn):
    helpers.create_project(db_conn, "proj-h", github_user="none")
    dev = helpers.create_device(db_conn, "dev-1", alias="thermostat")
    helpers.create_crash(db_conn, "proj-h", "1.0", dev)

    resp = client.get(f"{API}/devices/{dev}")
    assert resp.status_code == 200
    assert resp.get_json()["alias"] == "thermostat"


def test_project_settings_composite(client, db_conn):
    helpers.create_project(db_conn, "proj-i", github_user="none")
    helpers.create_webhook(db_conn, "proj-i", "https://example.com/hook")

    resp = client.get(f"{API}/projects/proj-i/settings")
    assert resp.status_code == 200
    body = resp.get_json()
    assert [w["webhook_url"] for w in body["webhooks"]] == ["https://example.com/hook"]
    assert body["acl"][0]["github"] == "none"


def test_acl_add_remove(client, db_conn):
    helpers.create_project(db_conn, "proj-j", github_user="none")

    added = client.post(f"{API}/projects/proj-j/acl", json={"github": "carol"}, headers=CSRF)
    assert added.status_code == 201

    listed = client.get(f"{API}/projects/proj-j/acl")
    assert {a["github"] for a in listed.get_json()} == {"none", "carol"}

    removed = client.delete(f"{API}/projects/proj-j/acl/carol", headers=CSRF)
    assert removed.status_code == 200


def test_device_url_template_validation(client, db_conn):
    helpers.create_project(db_conn, "proj-k", github_user="none")

    bad = client.put(f"{API}/projects/proj-k/settings/device-url", json={"device_url_template": "not-a-url"}, headers=CSRF)
    assert bad.status_code == 400

    good = client.put(
        f"{API}/projects/proj-k/settings/device-url",
        json={"device_url_template": "https://iot.example/{device_id}"},
        headers=CSRF,
    )
    assert good.status_code == 200

    fetched = client.get(f"{API}/projects/proj-k/settings/device-url")
    assert fetched.get_json()["device_url_template"] == "https://iot.example/{device_id}"


def test_unauthenticated_request_gets_json_401(github_auth_unauthenticated):
    resp = github_auth_unauthenticated.get(f"{API}/projects")
    assert resp.status_code == 401
    assert resp.get_json()["error"]["code"] == "unauthorized"


def test_authenticated_github_user_scoped(github_client, db_conn):
    helpers.create_project(db_conn, "alice-proj", github_user="alice")
    helpers.create_project(db_conn, "bob-proj", github_user="bob")

    alice = github_client("alice")
    resp = alice.get(f"{API}/projects")
    assert [p["project_name"] for p in resp.get_json()] == ["alice-proj"]


def test_cors_preflight_allowed_origin(client, monkeypatch):
    monkeypatch.setenv("API_CORS_ORIGINS", "http://localhost:5173")
    resp = client.options(
        f"{API}/projects",
        headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "GET"},
    )
    assert resp.headers.get("Access-Control-Allow-Origin") == "http://localhost:5173"


def test_cors_preflight_disallowed_origin(client, monkeypatch):
    monkeypatch.setenv("API_CORS_ORIGINS", "http://localhost:5173")
    resp = client.options(
        f"{API}/projects",
        headers={"Origin": "http://evil.example", "Access-Control-Request-Method": "GET"},
    )
    assert "Access-Control-Allow-Origin" not in resp.headers
