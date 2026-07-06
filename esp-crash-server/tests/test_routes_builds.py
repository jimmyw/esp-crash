import zipfile
import io

import helpers


def test_show_build_not_found(client):
    resp = client.get("/build/999999")
    assert resp.status_code == 400


def test_show_build_renders(client, db_conn):
    elf_id = helpers.create_elf_file(db_conn, "proj-bd", "1.0", project_alias="alias-1")
    resp = client.get(f"/build/{elf_id}")
    assert resp.status_code == 200
    assert b"alias-1" in resp.data


def test_update_build_alias(client, db_conn):
    elf_id = helpers.create_elf_file(db_conn, "proj-bd2", "1.0")
    resp = client.post(f"/build/{elf_id}", data={"alias": "new-alias"})
    assert resp.status_code == 200
    assert b"new-alias" in resp.data

    with db_conn.cursor() as cur:
        cur.execute("SELECT project_alias FROM elf_file WHERE elf_file_id = %s", (elf_id,))
        assert cur.fetchone()[0] == "new-alias"


def test_download_build_returns_zip(client, db_conn):
    elf_id = helpers.create_elf_file(db_conn, "proj-bd3", "1.0", elf_bytes=helpers.elf_file_bytes())
    resp = client.get(f"/build/{elf_id}/download")
    assert resp.status_code == 200
    assert resp.headers["Content-Type"] == "application/zip"

    zf = zipfile.ZipFile(io.BytesIO(resp.data))
    names = zf.namelist()
    assert any(name.endswith(f"elf_{elf_id}.elf") for name in names)


def test_delete_elf_not_found(client):
    resp = client.get("/elf/delete/999999")
    assert resp.status_code == 404


def test_delete_elf_removes_row_and_redirects(client, db_conn):
    elf_id = helpers.create_elf_file(db_conn, "proj-bd4", "1.0")
    resp = client.get(f"/elf/delete/{elf_id}")
    assert resp.status_code == 302
    assert resp.headers["Location"].endswith("/projects/proj-bd4/builds")

    with db_conn.cursor() as cur:
        cur.execute("SELECT 1 FROM elf_file WHERE elf_file_id = %s", (elf_id,))
        assert cur.fetchone() is None
