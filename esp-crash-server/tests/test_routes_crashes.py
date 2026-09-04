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


def test_reload_crash_summary_clears_title_and_summary_and_redirects(client, db_conn):
    helpers.create_project(db_conn, "proj-c4b", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c4b")
    sig = "f" * 64
    crash_id = helpers.create_crash(
        db_conn, "proj-c4b", "1.0", device_id, dump="symbolicated text",
        signature=sig, ai_title="Old title", ai_summary="Old summary",
    )

    resp = client.post(f"/projects/proj-c4b/{crash_id}/reload-summary")
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_title, ai_summary FROM crash_relation WHERE project_name = %s AND signature = %s", ("proj-c4b", sig))
        assert cur.fetchone() == (None, None)


def test_reload_crash_summary_clears_review_for_whole_group(client, db_conn):
    """ai_title/ai_summary are owned by the relation, not the crash -
    reloading via one crash clears the review for every crash sharing its
    signature."""
    helpers.create_project(db_conn, "proj-c4d", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c4d")
    sig = "g" * 64
    crash_a = helpers.create_crash(
        db_conn, "proj-c4d", "1.0", device_id, dump="dump a",
        signature=sig, ai_title="Shared title", ai_summary="Shared summary",
    )
    crash_b = helpers.create_crash(db_conn, "proj-c4d", "1.0", device_id, dump="dump b", signature=sig)

    resp = client.post(f"/projects/proj-c4d/{crash_a}/reload-summary")
    assert resp.status_code == 302

    resp_b = client.get(f"/projects/proj-c4d/{crash_b}")
    assert b"Shared title" not in resp_b.data
    assert b"Shared summary" not in resp_b.data


def test_reload_crash_summary_shows_review_again_button_when_summarized(client, db_conn):
    helpers.create_project(db_conn, "proj-c4c", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c4c")
    sig = "h" * 64
    crash_id = helpers.create_crash(
        db_conn, "proj-c4c", "1.0", device_id, dump="symbolicated text",
        signature=sig, ai_title="Some title", ai_summary="Some summary",
    )

    resp = client.get(f"/projects/proj-c4c/{crash_id}")
    assert resp.status_code == 200
    assert b"Review again" in resp.data


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
    sig = "i" * 64
    crash_id = helpers.create_crash(
        db_conn, "proj-c6", "1.0", device_id, signature=sig,
        dump="dump text", ai_summary="This crash is a stack overflow.",
    )
    resp = client.get(f"/projects/proj-c6/{crash_id}")
    assert resp.status_code == 200
    assert b"This crash is a stack overflow." in resp.data


def test_show_project_crash_ai_summary_preserves_newlines(client, db_conn):
    """The AI summary is prose Claude wrote with its own line breaks -
    plain HTML collapses those, so the summary block needs a whitespace
    CSS class that actually renders them."""
    helpers.create_project(db_conn, "proj-c7-ai-nl", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-c7-ai-nl")
    sig = "j" * 64
    crash_id = helpers.create_crash(
        db_conn, "proj-c7-ai-nl", "1.0", device_id, signature=sig,
        dump="dump text", ai_summary="First line.\nSecond line.",
    )
    resp = client.get(f"/projects/proj-c7-ai-nl/{crash_id}")
    assert resp.status_code == 200
    body = resp.data.decode()
    assert "First line.\nSecond line." in body
    assert "whitespace-pre-line" in body


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


# --- /c/<id>: the short link handed out by /dump ----------------------------

def test_short_link_redirects_to_the_project_scoped_page(client, db_conn):
    """A shared short link must land on the same URL as every in-app link, so
    the page, its bookmarks and the browser history all agree."""
    helpers.create_project(db_conn, "proj-short", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-short")
    crash_id = helpers.create_crash(db_conn, "proj-short", "1.0", device_id, dump="short link text")

    resp = client.get(f"/c/{crash_id}")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith(f"/projects/proj-short/{crash_id}")

    followed = client.get(f"/c/{crash_id}", follow_redirects=True)
    assert followed.status_code == 200
    assert b"short link text" in followed.data


def test_short_link_for_an_unknown_crash_is_404(client):
    assert client.get("/c/999999").status_code == 404


def test_short_link_for_an_inaccessible_crash_is_404_not_a_redirect(client, db_conn):
    """A crash the caller cannot see must be indistinguishable from one that
    does not exist. Redirecting would answer "which project is crash N in?"
    for anyone holding an id."""
    device_id = helpers.create_device(db_conn, "dev-short-noacl")
    # No project_auth row for this project, so it is not visible to anyone.
    crash_id = helpers.create_crash(db_conn, "proj-short-noacl", "1.0", device_id, dump="hidden")

    resp = client.get(f"/c/{crash_id}")
    assert resp.status_code == 404
    assert b"proj-short-noacl" not in resp.data


def test_short_link_rejects_a_non_numeric_id(client):
    """The int converter keeps junk out of the database comparison."""
    assert client.get("/c/not-a-number").status_code == 404
