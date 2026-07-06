import io
import zipfile

import helpers


def test_download_crash_not_found(client):
    resp = client.get("/crash/999999/download")
    assert resp.status_code == 404


def test_download_crash_without_elf_images(client, db_conn):
    helpers.create_project(db_conn, "proj-dl", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-dl")
    crash_id = helpers.create_crash(db_conn, "proj-dl", "1.0", device_id, crash_dmp=b"dump-content")

    resp = client.get(f"/crash/{crash_id}/download")
    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.data))
    assert any(name.endswith(f"crash_{crash_id}.dmp") for name in zf.namelist())


def test_download_crash_with_elf_resolves_modules_mocked(client, db_conn, monkeypatch):
    from app import decode

    helpers.create_project(db_conn, "proj-dl2", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-dl2")
    crash_id = helpers.create_crash(db_conn, "proj-dl2", "1.0", device_id, crash_dmp=b"dump-content")
    helpers.create_elf_file(db_conn, "proj-dl2", "1.0")

    def fake_resolve(dump_path, prog_path):
        return ([], [], "base text", None, ["# module test: symbols not available"])

    monkeypatch.setattr(decode, "_resolve_modules_for_dump", fake_resolve)

    resp = client.get(f"/crash/{crash_id}/download")
    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.data))
    names = zf.namelist()
    assert any(name.endswith(f"crash_{crash_id}.dmp") for name in names)
    assert any(name.endswith(".elf") for name in names)
