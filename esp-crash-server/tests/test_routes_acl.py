import helpers


def test_list_acl_redirects_to_settings(client, db_conn):
    helpers.create_project(db_conn, "proj-acl", github_user="none")
    resp = client.get("/projects/proj-acl/acl")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/projects/proj-acl/settings")


def test_create_acl_success(client, db_conn):
    helpers.create_project(db_conn, "proj-acl2", github_user="none")
    resp = client.post("/projects/proj-acl2/acl/create", data={"github": "octocat"})
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT github FROM project_auth WHERE project_name = %s AND github = %s",
            ("proj-acl2", "octocat"),
        )
        assert cur.fetchone() is not None


def test_create_acl_missing_github_400(client, db_conn):
    helpers.create_project(db_conn, "proj-acl3", github_user="none")
    resp = client.post("/projects/proj-acl3/acl/create", data={"github": ""})
    assert resp.status_code == 400


def test_create_acl_duplicate_400(client, db_conn):
    helpers.create_project(db_conn, "proj-acl4", github_user="none")
    client.post("/projects/proj-acl4/acl/create", data={"github": "octocat"})
    resp = client.post("/projects/proj-acl4/acl/create", data={"github": "octocat"})
    assert resp.status_code == 400


def test_create_acl_no_access_for_unregistered_project(client):
    resp = client.post("/projects/no-such-project/acl/create", data={"github": "octocat"})
    assert resp.status_code == 500


def test_delete_acl_removes_entry(client, db_conn):
    helpers.create_project(db_conn, "proj-acl5", github_user="none")
    helpers.create_project(db_conn, "proj-acl5", github_user="octocat")

    resp = client.get("/projects/proj-acl5/acl/delete/octocat")
    assert resp.status_code == 302

    with db_conn.cursor() as cur:
        cur.execute(
            "SELECT github FROM project_auth WHERE project_name = %s AND github = %s",
            ("proj-acl5", "octocat"),
        )
        assert cur.fetchone() is None
