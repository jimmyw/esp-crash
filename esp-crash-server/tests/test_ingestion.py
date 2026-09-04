import io

import helpers


def _upload_dump(client, content, filename="crash.dmp"):
    return client.post(
        "/dump",
        data={"file": (io.BytesIO(content), filename)},
        content_type="multipart/form-data",
    )


def test_dump_success_creates_device_and_crash(client, db_conn):
    content = helpers.crash_dump_bytes(project_name="proj-dump", project_ver="1.0", device_id="dev-dump-1")
    resp = _upload_dump(client, content)
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT device_id FROM device WHERE ext_device_id = %s", ("dev-dump-1",))
        assert cur.fetchone() is not None
        cur.execute("SELECT project_name, project_ver FROM crash WHERE project_name = %s", ("proj-dump",))
        row = cur.fetchone()
        assert row == ("proj-dump", "1.0")


def test_dump_accepts_precompressed_content(client, db_conn):
    content = helpers.crash_dump_bytes(project_name="proj-dump-c", project_ver="1.0", device_id="dev-dump-c", compressed=True)
    resp = _upload_dump(client, content)
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM crash WHERE project_name = %s", ("proj-dump-c",))
        assert cur.fetchone() is not None


def test_dump_missing_file_part(client):
    resp = client.post("/dump", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400


def test_dump_no_selected_file(client):
    resp = client.post(
        "/dump",
        data={"file": (io.BytesIO(b""), "")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_dump_missing_marker(client):
    resp = _upload_dump(client, b"not a real crash dump")
    assert resp.status_code == 400


def test_dump_rate_limited_after_five_per_hour(client, db_conn):
    device_id = helpers.create_device(db_conn, "dev-dump-rl")
    for _ in range(5):
        helpers.create_crash(db_conn, "proj-rl", "1.0", device_id)

    content = helpers.crash_dump_bytes(project_name="proj-rl", project_ver="1.0", device_id="dev-dump-rl")
    resp = _upload_dump(client, content)
    assert resp.status_code == 429


def test_upload_elf_with_marker(client, db_conn):
    content = helpers.elf_file_bytes(project_name="proj-elf", project_ver="1.0")
    resp = client.post(
        "/upload_elf",
        data={"file": (io.BytesIO(content), "build.elf")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM elf_file WHERE project_name = %s AND project_ver = %s", ("proj-elf", "1.0"))
        assert cur.fetchone() is not None


def test_upload_elf_with_explicit_form_fields(client, db_conn):
    content = helpers.elf_file_bytes(with_marker=False)
    resp = client.post(
        "/upload_elf",
        data={
            "file": (io.BytesIO(content), "build.elf"),
            "project_name": "proj-elf-2",
            "project_ver": "2.0",
        },
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM elf_file WHERE project_name = %s AND project_ver = %s", ("proj-elf-2", "2.0"))
        assert cur.fetchone() is not None


def test_upload_elf_missing_project_name_500(client):
    content = helpers.elf_file_bytes(with_marker=False)
    resp = client.post(
        "/upload_elf",
        data={"file": (io.BytesIO(content), "build.elf")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 500


def test_upload_elf_missing_file_500(client):
    resp = client.post("/upload_elf", data={}, content_type="multipart/form-data")
    assert resp.status_code == 500


def test_upload_module_elf_success(client, db_conn):
    resp = client.post(
        "/upload_module_elf",
        data={"file": (io.BytesIO(b"module-elf-bytes"), "mod.elf"), "name": "mymodule", "app_sha1": helpers.VALID_SHA1},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT name FROM module_elf WHERE app_sha1 = %s", (helpers.VALID_SHA1,))
        assert cur.fetchone()[0] == "mymodule"


def test_upload_module_elf_missing_name(client):
    resp = client.post(
        "/upload_module_elf",
        data={"file": (io.BytesIO(b"data"), "mod.elf"), "app_sha1": helpers.VALID_SHA1},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_upload_module_elf_bad_sha1(client):
    resp = client.post(
        "/upload_module_elf",
        data={"file": (io.BytesIO(b"data"), "mod.elf"), "name": "mymodule", "app_sha1": helpers.INVALID_SHA1},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400


def test_upload_module_elf_conflict_does_nothing(client, db_conn):
    sha1 = "b" * 40
    data = {"file": (io.BytesIO(b"first"), "mod.elf"), "name": "mod-a", "app_sha1": sha1}
    resp1 = client.post("/upload_module_elf", data=data, content_type="multipart/form-data")
    assert resp1.status_code == 200

    data2 = {"file": (io.BytesIO(b"second"), "mod.elf"), "name": "mod-a-renamed", "app_sha1": sha1}
    resp2 = client.post("/upload_module_elf", data=data2, content_type="multipart/form-data")
    assert resp2.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT name FROM module_elf WHERE app_sha1 = %s", (sha1,))
        rows = cur.fetchall()
        assert len(rows) == 1
        assert rows[0][0] == "mod-a"


def test_dump_returns_a_short_link_to_the_stored_crash(client, db_conn):
    """Whatever uploaded the crash knows its id and nothing else, so the
    response carries a link it can log or forward."""
    content = helpers.crash_dump_bytes(project_name="proj-dump-link", project_ver="1.0",
                                       device_id="dev-dump-link")
    resp = _upload_dump(client, content)
    assert resp.status_code == 200

    with db_conn.cursor() as cur:
        cur.execute("SELECT crash_id FROM crash WHERE project_name = %s", ("proj-dump-link",))
        crash_id = cur.fetchone()[0]

    body = resp.data.decode()
    assert f"/c/{crash_id}" in body, body
    # The "OK" prefix is kept for devices already in the field.
    assert body.startswith("OK ")


def test_dump_short_link_resolves_to_the_crash(client, db_conn):
    """End to end: the link the device is handed is one a person can open."""
    helpers.create_project(db_conn, "proj-dump-follow", github_user="none")
    content = helpers.crash_dump_bytes(project_name="proj-dump-follow", project_ver="1.0",
                                       device_id="dev-dump-follow")
    resp = _upload_dump(client, content)
    path = resp.data.decode().split()[1]
    path = path[path.index("/c/"):].strip()

    followed = client.get(path)
    assert followed.status_code == 302
    assert "/projects/proj-dump-follow/" in followed.headers["Location"]
