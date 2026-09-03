import io
import json
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


def test_download_crash_with_elf(client, db_conn):
    """No decoder is involved any more: the zip is assembled from stored rows,
    so a plain file download does not depend on the debug service or on a
    toolchain being present in this image."""
    helpers.create_project(db_conn, "proj-dl2", github_user="none")
    device_id = helpers.create_device(db_conn, "dev-dl2")
    crash_id = helpers.create_crash(db_conn, "proj-dl2", "1.0", device_id, crash_dmp=b"dump-content")
    helpers.create_elf_file(db_conn, "proj-dl2", "1.0")

    resp = client.get(f"/crash/{crash_id}/download")
    assert resp.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(resp.data)).namelist()
    assert any(name.endswith(f"crash_{crash_id}.dmp") for name in names)
    assert any(name.endswith(".elf") for name in names)


def set_module_map(db_conn, crash_id, module_map):
    with db_conn.cursor() as cur:
        cur.execute("UPDATE crash SET module_map = %s::jsonb WHERE crash_id = %s",
                    (json.dumps(module_map), crash_id))


def seed_module_crash(db_conn, project, module_map, *, upload_symbols=True):
    helpers.create_project(db_conn, project, github_user="none")
    device_id = helpers.create_device(db_conn, f"dev-{project}")
    crash_id = helpers.create_crash(db_conn, project, "1.0", device_id,
                                    crash_dmp=b"dump-content")
    helpers.create_elf_file(db_conn, project, "1.0")
    if upload_symbols:
        for module in module_map:
            helpers.create_module_elf(db_conn, module["name"], module["sha1"],
                                      elf_bytes=f"ELF-{module['name']}".encode())
    set_module_map(db_conn, crash_id, module_map)
    return crash_id


PLACED = [{"name": "ems-goodwe", "version": "1.2", "sha1": "a" * 40,
           "text": 0x4023639c, "data": 0x3ffe3a44, "bss": 0x3ffe3a6c,
           "rodata": 0x3f4c065c, "symbols": True}]


def test_the_zip_builds_a_gdbinit_from_the_stored_section_addresses(client, db_conn):
    """module_map records where each module was loaded, so the addresses no
    longer have to be recovered by running a debugger over the core."""
    crash_id = seed_module_crash(db_conn, "proj-mods", PLACED)

    resp = client.get(f"/crash/{crash_id}/download")
    assert resp.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(resp.data))
    names = zf.namelist()

    assert f"crash_{crash_id}/modules/ems-goodwe.elf" in names
    gdbinit = zf.read(f"crash_{crash_id}/module_symbols.gdbinit").decode()
    assert "add-symbol-file modules/ems-goodwe.elf 0x4023639c" in gdbinit
    assert "-s .data 0x3ffe3a44" in gdbinit
    assert "-s .bss 0x3ffe3a6c" in gdbinit
    assert "-s .rodata 0x3f4c065c" in gdbinit
    # The launcher must point gdb at it.
    script = next(zf.read(n).decode() for n in names if n.endswith(".sh"))
    assert "--extra-gdbinit-file module_symbols.gdbinit" in script


def test_a_module_whose_symbols_were_never_uploaded_is_explained(client, db_conn):
    crash_id = seed_module_crash(db_conn, "proj-nosym", PLACED, upload_symbols=False)

    zf = zipfile.ZipFile(io.BytesIO(client.get(f"/crash/{crash_id}/download").data))
    readme = zf.read(f"crash_{crash_id}/MODULES_README.txt").decode()
    assert "symbols not available" in readme
    assert f"crash_{crash_id}/module_symbols.gdbinit" not in zf.namelist()


def test_a_crash_decoded_before_addresses_were_recorded_degrades_with_a_reason(
        client, db_conn):
    """Older rows have module names but no placement, and it cannot be
    reconstructed without re-decoding. The package stays useful and says so
    rather than silently omitting the module symbols."""
    legacy = [{"name": "ems-goodwe", "version": "1.2", "sha1": "a" * 40}]
    crash_id = seed_module_crash(db_conn, "proj-legacy", legacy)

    zf = zipfile.ZipFile(io.BytesIO(client.get(f"/crash/{crash_id}/download").data))
    assert f"crash_{crash_id}/module_symbols.gdbinit" not in zf.namelist()
    readme = zf.read(f"crash_{crash_id}/MODULES_README.txt").decode()
    assert "decoded before module section addresses were recorded" in readme
    assert "Regenerate crash" in readme, "must say how to fix it"
