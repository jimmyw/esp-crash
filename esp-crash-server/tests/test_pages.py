import helpers


def test_dashboard_renders(client):
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert b"Dashboard" in resp.data


def test_settings_renders(client):
    resp = client.get("/settings")
    assert resp.status_code == 200
    assert b"Settings" in resp.data


def test_index_renders_with_no_projects(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Register new project" in resp.data


def test_index_lists_seeded_projects(client, db_conn):
    helpers.create_project(db_conn, "proj-a", github_user="none")
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"proj-a" in resp.data
