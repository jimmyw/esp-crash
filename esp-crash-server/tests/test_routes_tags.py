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


def test_add_crash_tag_new_tag_name_takes_priority(client, db_conn):
    """Picking an existing tag in the dropdown AND typing a new one submits
    both form fields - the typed one must win, matching what it looks like
    the form does."""
    helpers.create_project(db_conn, "proj-t1b", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t1b")
    crash_id = helpers.create_crash(db_conn, "proj-t1b", "1.0", device_id)
    helpers.create_tag(db_conn, "proj-t1b", "existing")

    resp = client.post(
        f"/projects/proj-t1b/{crash_id}/tags",
        data={"tag_name": "existing", "new_tag_name": "Brand New"},
    )
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT t.name FROM tag t JOIN crash_tag ct ON ct.tag_id = t.tag_id WHERE ct.crash_id = %s",
            (crash_id,),
        )
        assert cur.fetchone()[0] == "brand new"


def test_add_crash_tag_new_tag_sentinel_uses_typed_name(client, db_conn):
    """Selecting the "+ New tag..." option submits tag_name=__new_tag__
    alongside the typed new_tag_name - the sentinel itself must never
    become the tag name."""
    helpers.create_project(db_conn, "proj-t1c", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t1c")
    crash_id = helpers.create_crash(db_conn, "proj-t1c", "1.0", device_id)

    resp = client.post(
        f"/projects/proj-t1c/{crash_id}/tags",
        data={"tag_name": "__new_tag__", "new_tag_name": "Flaky Sensor"},
    )
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute("SELECT name FROM tag WHERE project_name = %s", ("proj-t1c",))
        assert cur.fetchone() == ("flaky sensor",)


def test_add_crash_tag_new_tag_sentinel_without_typed_name_is_missing(client, db_conn):
    """The sentinel alone (JS didn't run, or the field was left empty) must
    be rejected like any other missing tag name, not create a tag
    literally called "__new_tag__"."""
    helpers.create_project(db_conn, "proj-t1d", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t1d")
    crash_id = helpers.create_crash(db_conn, "proj-t1d", "1.0", device_id)

    resp = client.post(f"/projects/proj-t1d/{crash_id}/tags", data={"tag_name": "__new_tag__"})
    assert resp.status_code == 400

    with db_conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM tag WHERE project_name = %s", ("proj-t1d",))
        assert cur.fetchone()[0] == 0


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
    # Tag badges display uppercase (CSS only - stored name stays lowercase).
    assert 'class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium uppercase' in resp.data.decode()


def test_crash_page_tag_picker_is_a_visible_select(client, db_conn):
    """The add-tag picker must be a real <select> listing the project's
    existing tags, not an <input list>/<datalist> pair that renders as an
    apparently-empty text box until you start typing."""
    helpers.create_project(db_conn, "proj-t4b", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t4b")
    crash_id = helpers.create_crash(db_conn, "proj-t4b", "1.0", device_id)
    # A tag that exists for the project but isn't attached to this crash yet -
    # exactly what the picker needs to show.
    helpers.create_tag(db_conn, "proj-t4b", "unattached-tag", description="pick me")

    resp = client.get(f"/projects/proj-t4b/{crash_id}")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert '<select name="tag_name"' in body
    assert '<option value="unattached-tag"' in body
    assert "<datalist" not in body
    assert 'name="new_tag_name"' in body


def test_crash_page_new_tag_fields_are_hidden_until_new_tag_selected(client, db_conn):
    """The new-tag name/description inputs must start hidden - they're
    only meant to appear once "+ New tag..." is picked in the dropdown."""
    helpers.create_project(db_conn, "proj-t4c", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t4c")
    crash_id = helpers.create_crash(db_conn, "proj-t4c", "1.0", device_id)

    resp = client.get(f"/projects/proj-t4c/{crash_id}")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert '<option value="__new_tag__">+ New tag' in body
    assert 'id="new-tag-fields"' in body
    assert 'style="display:none"' in body


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


def test_list_project_crashes_tags_sorted_uppercase(client, db_conn):
    helpers.create_project(db_conn, "proj-t6", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-t6")
    crash_id = helpers.create_crash(db_conn, "proj-t6", "1.0", device_id)
    # Inserted out of alphabetical order - the rendered badges must not be.
    tag_z = helpers.create_tag(db_conn, "proj-t6", "zzztagz")
    tag_a = helpers.create_tag(db_conn, "proj-t6", "aaataga")
    tag_m = helpers.create_tag(db_conn, "proj-t6", "mmmtagm")
    for tag_id in (tag_z, tag_a, tag_m):
        helpers.tag_crash(db_conn, crash_id, tag_id)

    resp = client.get("/projects/proj-t6")
    assert resp.status_code == 200
    body = resp.data.decode()
    # Badges render lowercase tag names uppercased purely via CSS, so the
    # underlying stored casing (and click-to-filter matching) is untouched -
    # assert ordering on the stored names and the CSS class that uppercases them.
    assert body.index("aaataga") < body.index("mmmtagm") < body.index("zzztagz")
    assert 'class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium uppercase' in body
