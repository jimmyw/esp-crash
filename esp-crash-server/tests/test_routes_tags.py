import helpers


def test_add_crash_tag_creates_and_redirects(client, db_conn):
    helpers.create_project(db_conn, "proj-t1", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t1")
    crash_id = helpers.create_crash(db_conn, "proj-t1", "1.0", device_id)

    resp = client.post(
        f"/projects/proj-t1/{crash_id}/tags",
        data={"tag_name": "Reviewed", "tag_description": "Looked at"},
    )
    assert resp.status_code == 302
    assert resp.headers["Location"] == f"/projects/proj-t1/{crash_id}"

    with db_conn.cursor() as cur:
        cur.execute("SELECT name, description FROM tag WHERE project_name = %s", ("proj-t1",))
        assert cur.fetchone() == ("reviewed", "Looked at")  # case-folded


def test_add_crash_tag_requires_name(client, db_conn):
    helpers.create_project(db_conn, "proj-t2", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t2")
    crash_id = helpers.create_crash(db_conn, "proj-t2", "1.0", device_id)

    resp = client.post(f"/projects/proj-t2/{crash_id}/tags", data={"tag_name": ""})
    assert resp.status_code == 400


def test_remove_crash_tag(client, db_conn):
    helpers.create_project(db_conn, "proj-t3", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t3")
    crash_id = helpers.create_crash(db_conn, "proj-t3", "1.0", device_id)
    tag_id = helpers.create_tag(db_conn, "proj-t3", "wontfix")
    helpers.tag_crash(db_conn, crash_id, tag_id)

    resp = client.post(f"/projects/proj-t3/{crash_id}/tags/{tag_id}/remove")
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM crash_tag WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == 0


def test_crash_page_shows_tag_badge(client, db_conn):
    helpers.create_project(db_conn, "proj-t4", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t4")
    crash_id = helpers.create_crash(db_conn, "proj-t4", "1.0", device_id)
    tag_id = helpers.create_tag(db_conn, "proj-t4", "duplicate", description="Dup of #1")
    helpers.tag_crash(db_conn, crash_id, tag_id)

    resp = client.get(f"/projects/proj-t4/{crash_id}")
    assert resp.status_code == 200
    assert b"duplicate" in resp.data


def test_list_project_crashes_tag_filter(client, db_conn):
    helpers.create_project(db_conn, "proj-t5", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t5")
    crash_1 = helpers.create_crash(db_conn, "proj-t5", "1.0", device_id)
    helpers.create_crash(db_conn, "proj-t5", "1.0", device_id)
    tag_id = helpers.create_tag(db_conn, "proj-t5", "wontfix")
    helpers.tag_crash(db_conn, crash_1, tag_id)

    resp = client.get(f"/projects/proj-t5?tag_id={tag_id}")
    assert resp.status_code == 200
    assert b"Filtered by tag" in resp.data
