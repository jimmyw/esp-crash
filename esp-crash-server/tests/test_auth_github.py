import helpers


def test_unauthenticated_redirects_to_github_login(github_auth_unauthenticated):
    resp = github_auth_unauthenticated.get("/dashboard")
    assert resp.status_code == 302
    assert "/login/github" in resp.headers["Location"]


def test_project_settings_forbidden_for_non_owner(db_conn, github_client):
    helpers.create_project(db_conn, "proj-gh-acl", github_user="userA")
    other_user_client = github_client("userB")
    resp = other_user_client.get("/projects/proj-gh-acl/settings")
    assert resp.status_code == 403


def test_project_settings_allowed_for_owner(db_conn, github_client):
    helpers.create_project(db_conn, "proj-gh-acl2", github_user="userA")
    owner_client = github_client("userA")
    resp = owner_client.get("/projects/proj-gh-acl2/settings")
    assert resp.status_code == 200
    assert b"proj-gh-acl2" in resp.data


def test_download_crash_not_visible_to_other_user(db_conn, github_client):
    helpers.create_project(db_conn, "proj-gh-acl3", github_user="userA")
    device_id = helpers.create_device(db_conn, "dev-gh-1")
    crash_id = helpers.create_crash(db_conn, "proj-gh-acl3", "1.0", device_id, crash_dmp=b"dump-content")

    other_user_client = github_client("userB")
    resp = other_user_client.get(f"/crash/{crash_id}/download")
    assert resp.status_code == 404

    owner_client = github_client("userA")
    resp = owner_client.get(f"/crash/{crash_id}/download")
    assert resp.status_code == 200
