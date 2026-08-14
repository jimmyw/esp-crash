import helpers


def test_show_project_crash_not_found(client, db_conn):
    helpers.create_project(db_conn, "proj-c", github_user="none")
    resp = client.get("/projects/proj-c/999999")
    assert resp.status_code == 404


def test_show_project_crash_renders(client, db_conn):
    helpers.create_project(db_conn, "proj-c2", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c2")
    crash_id = helpers.create_crash(db_conn, "proj-c2", "1.0", device_id, dump="some symbolicated text")
    resp = client.get(f"/projects/proj-c2/{crash_id}")
    assert resp.status_code == 200
    assert b"some symbolicated text" in resp.data


def test_show_crash_shorthand_redirect_route(client, db_conn):
    helpers.create_project(db_conn, "proj-c3", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c3")
    crash_id = helpers.create_crash(db_conn, "proj-c3", "1.0", device_id, dump="dump text")
    resp = client.get(f"/crash/{crash_id}")
    assert resp.status_code == 200
    assert b"dump text" in resp.data


def test_refresh_crash_clears_dump_and_redirects(client, db_conn):
    helpers.create_project(db_conn, "proj-c4", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c4")
    crash_id = helpers.create_crash(db_conn, "proj-c4", "1.0", device_id, dump="stale dump")

    resp = client.get(f"/projects/proj-c4/{crash_id}/refresh")
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute("SELECT dump FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] is None


def test_show_project_crash_shows_related_link_when_signature_set(client, db_conn):
    helpers.create_project(db_conn, "proj-c7", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c7")
    sig = "d" * 64
    crash_id = helpers.create_crash(db_conn, "proj-c7", "1.0", device_id, dump="dump text", signature=sig)

    resp = client.get(f"/projects/proj-c7/{crash_id}")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert f"/crash?signature={sig}" in body
    assert "Related" in body


def test_show_project_crash_hides_related_link_without_signature(client, db_conn):
    helpers.create_project(db_conn, "proj-c8", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c8")
    crash_id = helpers.create_crash(db_conn, "proj-c8", "1.0", device_id, dump="dump text")

    resp = client.get(f"/projects/proj-c8/{crash_id}")
    assert resp.status_code == 200
    assert b"signature=" not in resp.data


def test_show_project_crash_renders_ai_summary(client, db_conn):
    helpers.create_project(db_conn, "proj-c6", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c6")
    crash_id = helpers.create_crash(
        db_conn, "proj-c6", "1.0", device_id,
        dump="dump text", ai_summary="This crash is a stack overflow.",
    )
    resp = client.get(f"/projects/proj-c6/{crash_id}")
    assert resp.status_code == 200
    assert b"This crash is a stack overflow." in resp.data


def test_show_project_crash_omits_ai_summary_block_when_absent(client, db_conn):
    helpers.create_project(db_conn, "proj-c7", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c7")
    crash_id = helpers.create_crash(db_conn, "proj-c7", "1.0", device_id, dump="dump text")
    resp = client.get(f"/projects/proj-c7/{crash_id}")
    assert resp.status_code == 200
    assert b"bg-indigo-50" not in resp.data


def test_delete_crash_removes_row_and_redirects(client, db_conn):
    helpers.create_project(db_conn, "proj-c5", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c5")
    crash_id = helpers.create_crash(db_conn, "proj-c5", "1.0", device_id)

    resp = client.get(f"/projects/proj-c5/{crash_id}/delete")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "/projects/proj-c5"

    with db_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone() is None
