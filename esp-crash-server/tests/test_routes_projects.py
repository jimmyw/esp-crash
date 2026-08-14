import helpers


def test_create_project_success_redirects(client):
    resp = client.post("/projects/create", data={"project_name": "new-proj"})
    assert resp.status_code == 302
    assert "/projects/new-proj" in resp.headers["Location"]


def test_create_project_missing_name_400(client):
    resp = client.post("/projects/create", data={"project_name": ""})
    assert resp.status_code == 400


def test_create_project_duplicate_400(client, db_conn):
    helpers.create_project(db_conn, "dup-proj", github_user="none")
    resp = client.post("/projects/create", data={"project_name": "dup-proj"})
    assert resp.status_code == 400


def test_list_project_crashes_empty(client, db_conn):
    helpers.create_project(db_conn, "proj-x", github_user="none")
    resp = client.get("/projects/proj-x")
    assert resp.status_code == 200
    assert b"proj-x" in resp.data


def test_list_project_crashes_shows_seeded_crash(client, db_conn):
    helpers.create_project(db_conn, "proj-y", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-1")
    helpers.create_crash(db_conn, "proj-y", "1.0", device_id, dump="some dump text")
    resp = client.get("/projects/proj-y")
    assert resp.status_code == 200
    assert b"dev-1" in resp.data


def test_list_project_crashes_search_filters(client, db_conn):
    helpers.create_project(db_conn, "proj-z", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-2")
    helpers.create_crash(db_conn, "proj-z", "2.0", device_id)
    resp = client.get("/projects/proj-z?search=nonexistent-term")
    assert resp.status_code == 200
    assert b"dev-2" not in resp.data


def test_list_crashes_all_projects(client, db_conn):
    helpers.create_project(db_conn, "proj-all", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-3")
    helpers.create_crash(db_conn, "proj-all", "1.0", device_id)
    resp = client.get("/crash")
    assert resp.status_code == 200
    assert b"dev-3" in resp.data


def test_list_project_crashes_signature_filter(client, db_conn):
    helpers.create_project(db_conn, "proj-sig", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-sig")
    sig = "b" * 64
    helpers.create_crash(db_conn, "proj-sig", "1.0", device_id, signature=sig)
    helpers.create_crash(db_conn, "proj-sig", "1.0", device_id)  # no signature - must not match

    resp = client.get(f"/projects/proj-sig?signature={sig}")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "Related crashes matching signature" in body
    assert sig[:12] in body


def test_list_crashes_signature_filter_spans_projects(client, db_conn):
    """The Related link on the crash page points at the global /crash
    listing (not a per-project one) - a signature match must be found
    regardless of which project it's in."""
    sig = "c" * 64
    helpers.create_project(db_conn, "proj-sig-a", github_user="none")
    device_a = helpers.create_device(db_conn, "dev-sig-a")
    helpers.create_crash(db_conn, "proj-sig-a", "1.0", device_a, signature=sig)

    helpers.create_project(db_conn, "proj-sig-b", github_user="none")
    device_b = helpers.create_device(db_conn, "dev-sig-b")
    helpers.create_crash(db_conn, "proj-sig-b", "1.0", device_b, signature=sig)

    resp = client.get(f"/crash?signature={sig}")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "proj-sig-a" in body
    assert "proj-sig-b" in body


def test_list_project_crashes_shows_related_link_with_count(client, db_conn):
    helpers.create_project(db_conn, "proj-related", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-related")
    sig = "e" * 64
    helpers.create_crash(db_conn, "proj-related", "1.0", device_id, signature=sig)
    helpers.create_crash(db_conn, "proj-related", "1.0", device_id, signature=sig)
    helpers.create_crash(db_conn, "proj-related", "1.0", device_id, signature=sig)

    resp = client.get("/projects/proj-related")
    assert resp.status_code == 200
    body = resp.data.decode()
    # Each of the 3 crashes shares its signature with the other 2.
    assert body.count("Related(2)") == 3
    assert f"signature={sig}" in body


def test_list_project_crashes_hides_related_link_without_duplicates(client, db_conn):
    helpers.create_project(db_conn, "proj-no-related", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-no-related")
    # A signature with no other crash sharing it, and a crash with no
    # signature at all - neither should render a Related link.
    helpers.create_crash(db_conn, "proj-no-related", "1.0", device_id, signature="f" * 64)
    helpers.create_crash(db_conn, "proj-no-related", "1.0", device_id)

    resp = client.get("/projects/proj-no-related")
    assert resp.status_code == 200
    assert "Related(" not in resp.data.decode()


def test_related_count_not_inflated_by_multiple_acl_grants(client, db_conn):
    """A project with more than one project_auth row (multiple users
    granted access) must not fan-out the related-crash count - regression
    test for the ProjectAuth join used to compute it."""
    helpers.create_project(db_conn, "proj-related-multi-acl", github_user="alice")
    helpers.create_project(db_conn, "proj-related-multi-acl", github_user="bob")
    device_id = helpers.create_device(db_conn, "dev-related-multi-acl")
    sig = "1" * 64
    helpers.create_crash(db_conn, "proj-related-multi-acl", "1.0", device_id, signature=sig)
    helpers.create_crash(db_conn, "proj-related-multi-acl", "1.0", device_id, signature=sig)

    resp = client.get("/projects/proj-related-multi-acl")
    assert resp.status_code == 200
    assert "Related(1)" in resp.data.decode()


def test_list_builds_empty(client, db_conn):
    helpers.create_project(db_conn, "proj-b", github_user="none")
    resp = client.get("/projects/proj-b/builds")
    assert resp.status_code == 200


def test_list_builds_shows_seeded_elf(client, db_conn):
    helpers.create_project(db_conn, "proj-b2", github_user="none")
    helpers.create_elf_file(db_conn, "proj-b2", "1.0", project_alias="my-alias")
    resp = client.get("/projects/proj-b2/builds")
    assert resp.status_code == 200
    assert b"my-alias" in resp.data


def test_project_settings_forbidden_for_unregistered_project(client):
    resp = client.get("/projects/no-such-project/settings")
    assert resp.status_code == 403


def test_project_settings_renders_for_registered_project(client, db_conn):
    helpers.create_project(db_conn, "proj-s", github_user="none")
    resp = client.get("/projects/proj-s/settings")
    assert resp.status_code == 200
    assert b"proj-s" in resp.data


def test_device_url_admin_valid_template(client, db_conn):
    helpers.create_project(db_conn, "proj-d", github_user="none")
    resp = client.post(
        "/projects/proj-d/settings/device-url",
        data={"device_url_template": "https://x.test/{device_id}"},
    )
    assert resp.status_code == 302
    assert "device_url_error" not in resp.headers["Location"]

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT device_url_template FROM project_settings WHERE project_name = %s",
            ("proj-d",),
        )
        row = cur.fetchone()
    assert row[0] == "https://x.test/{device_id}"


def test_device_url_admin_invalid_template_redirects_with_error(client, db_conn):
    helpers.create_project(db_conn, "proj-d2", github_user="none")
    resp = client.post(
        "/projects/proj-d2/settings/device-url",
        data={"device_url_template": "javascript:alert(1)/{device_id}"},
    )
    assert resp.status_code == 302
    assert "device_url_error=1" in resp.headers["Location"]


def test_webhooks_add_and_delete(client, db_conn):
    helpers.create_project(db_conn, "proj-w", github_user="none")

    resp = client.post(
        "/projects/proj-w/webhooks",
        data={"action": "add", "webhook_url": "https://hooks.test/abc"},
    )
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT webhook_id FROM project_webhooks WHERE project_name = %s",
            ("proj-w",),
        )
        webhook_id = cur.fetchone()[0]

    resp = client.post(
        "/projects/proj-w/webhooks",
        data={"action": "delete", "webhook_id": webhook_id},
    )
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT COUNT(*) FROM project_webhooks WHERE project_name = %s",
            ("proj-w",),
        )
        assert cur.fetchone()[0] == 0


def test_webhooks_forbidden_for_unregistered_project(client):
    resp = client.post(
        "/projects/no-such-project/webhooks",
        data={"action": "add", "webhook_url": "https://hooks.test/abc"},
    )
    assert resp.status_code == 403
