"""Crash detail, refresh, delete, and download. Mechanical move from
server.py - routes and logic unchanged, endpoint names preserved exactly
(registered directly on the app object, not via Flask Blueprint - see
core.py for why)."""
import os
import re
import bz2
import tempfile
import zipfile

from flask import redirect, send_file, url_for

from .. import decode
from ..auth import auth_clause, auth_project_in_clause, login_required
from ..db import ldb
from ..rendering import render_template


@login_required
def show_crash(crash_id):
    """Redirect to crash details, inferring the project name."""
    return show_project_crash(None, crash_id)


@login_required
def show_project_crash(project_name, crash_id):
    """Display crash details for a project."""

    # Fetch crash data from database
    auth_where, auth_args = auth_clause("project_auth.github")
    crash = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, crash.device_id, crash.project_ver, crash.crash_dmp, device.ext_device_id, COALESCE(device.alias, '') as device_alias, crash.dump, project_settings.device_url_template, crash.module_map
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        JOIN
            device USING (device_id)
        LEFT JOIN
            project_settings USING (project_name)
        WHERE
            crash_id = %s AND """ + auth_where + """
        ORDER BY
            date DESC""", (crash_id,) + auth_args)
    # If no crash data is found, return "Not found"
    if len(crash) != 1:
        return "Not found", 404

    crash = crash[0]

    # Fetch all elf image data from database that matches this project and version
    elf_images = ldb().get_data("SELECT elf_file_id, date, project_name, project_ver, file_size, project_alias FROM elf_file WHERE project_name = %s AND project_ver = %s ORDER BY date DESC", (crash["project_name"], crash["project_ver"], ))

    # Module tags come from the persisted module_map (written at cron time).
    # Availability is computed live because a module ELF may be uploaded after
    # the crash was processed.
    modules_for_ui = []
    for e in (crash.get("module_map") or []):
        sha1 = e.get("sha1", "")
        row = ldb().get_data(
            "SELECT module_elf_id FROM module_elf WHERE app_sha1 = %s LIMIT 1", (sha1,)
        )
        modules_for_ui.append({
            "name": e.get("name", ""),
            "version": e.get("version", ""),
            "sha1_short": sha1[:8],
            "sha1_full": sha1,
            "available": bool(row),
        })

    return render_template('crash.html', crash = crash, elf_images = elf_images, dump = crash["dump"], modules = modules_for_ui)


@login_required
def refresh_crash(project_name, crash_id):
    """Clear cached dump data so it will be reprocessed."""

    # Fetch crash data from database
    auth_where, auth_args = auth_clause("project_auth.github")
    refresh = """
        UPDATE
            crash
        SET
            dump = NULL
        FROM
            project_auth
        WHERE
            crash.crash_id = %s AND crash.project_name = project_auth.project_name AND """ + auth_where + """
        """

    c = ldb().cursor()
    c.execute(refresh, (crash_id,) + auth_args)
    ldb().commit()

    return redirect(url_for('show_project_crash', project_name=project_name, crash_id=crash_id))


@login_required
def download_crash(crash_id):
    """Download a crash dump along with related ELF files."""

    # Fetch crash data from database
    auth_where, auth_args = auth_clause("project_auth.github")
    crash = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, device.ext_device_id, crash.project_ver, crash.crash_dmp
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        JOIN
            device USING (device_id)
        WHERE
            crash_id = %s AND """ + auth_where + """
        ORDER BY
            date DESC""", (crash_id,) + auth_args)
    # If no crash data is found, return "Not found"
    if len(crash) != 1:
        return "Not found", 404

    crash = crash[0]

    # Fetch all elf image data from database that matches this project and version
    elf_images = ldb().get_data("SELECT elf_file_id, date, project_name, project_ver, elf_file FROM elf_file WHERE project_name = %s AND project_ver = %s ORDER BY date DESC", (crash["project_name"], crash["project_ver"], ))

    zipf = tempfile.NamedTemporaryFile(delete=False)
    with zipfile.ZipFile(zipf.name, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        dmp = tempfile.NamedTemporaryFile(delete=False)
        # Decompress crash_dmp and elf_file before writing to temp files
        try:
            decompressed_crash_dmp = bz2.decompress(crash["crash_dmp"])
        except IOError:
            decompressed_crash_dmp = crash["crash_dmp"]
        dmp.write(decompressed_crash_dmp)
        dmp.close()
        zip_file.write(dmp.name,  arcname="crash_{}/crash_{}.dmp".format(crash_id, crash_id))

        # Read the registry and resolve module ELFs so the package can ship the
        # module debug ELFs plus a generated gdbinit with literal add-symbol-file
        # lines (no gdb-Python needed). Reading needs the program ELF, so use the
        # first (most recent) elf_image.
        prog_tmp = None
        loaded = []
        core_elf = None
        mod_status = []
        try:
            if elf_images:
                try:
                    first = bz2.decompress(elf_images[0]["elf_file"])
                except IOError:
                    first = elf_images[0]["elf_file"]
                with tempfile.NamedTemporaryFile(suffix=".elf", delete=False, prefix="prog_") as pf:
                    pf.write(first)
                    prog_tmp = pf.name
                _regs, loaded, _base, core_elf, mod_status = \
                    decode._resolve_modules_for_dump(ldb(), dmp.name, prog_tmp)
            gdbinit_lines = []
            if loaded:
                for m in loaded:
                    safe = re.sub(r'[^A-Za-z0-9._-]', '_', m["name"])
                    arc = "modules/{}.elf".format(safe)
                    zip_file.write(m["elf"], arcname="crash_{}/{}".format(crash_id, arc))
                    gdbinit_lines.append(
                        "add-symbol-file {arc} {text:#x} -s .data {data:#x} "
                        "-s .bss {bss:#x} -s .rodata {rodata:#x}".format(
                            arc=arc, text=m["text"], data=m["data"],
                            bss=m["bss"], rodata=m["rodata"])
                    )
                zip_file.writestr(
                    "crash_{}/module_symbols.gdbinit".format(crash_id),
                    "# Literal add-symbol-file lines for this crash's modules.\n"
                    "# Run gdb from this directory so the relative module paths\n"
                    "# resolve. No gdb-Python required.\n"
                    + "\n".join(gdbinit_lines) + "\n",
                )
                missing = [s for s in mod_status if "symbols not available" in s]
                if missing:
                    zip_file.writestr(
                        "crash_{}/MODULES_README.txt".format(crash_id),
                        "Modules referenced by this crash with no uploaded symbols "
                        "(their frames will not be symbolicated):\n\n" + "\n".join(missing) + "\n",
                    )

            for elf_image in elf_images:
                # Create temporary files to store crash and elf data
                elf = tempfile.NamedTemporaryFile(delete=False)

                try:
                    decompressed_elf_file = bz2.decompress(elf_image["elf_file"])
                except IOError:
                    decompressed_elf_file = elf_image["elf_file"]

                # Write decompressed data to temporary files
                elf.write(decompressed_elf_file)
                elf.close()

                # Add files to zip
                zip_file.write(elf.name, arcname="crash_{}/elf_{}.elf".format(crash_id, elf_image["elf_file_id"]))

                os.unlink(elf.name)

                core_arc = "crash_{}.dmp".format(crash_id)
                elf_arc = "elf_{}.elf".format(elf_image["elf_file_id"])
                lines = ["#!/bin/bash", 'cd "$(dirname "$0")"', ". $ESP_IDF/export.sh"]
                if gdbinit_lines:
                    lines.insert(1, "# Launches esp-coredump with module symbols pre-loaded.")
                    lines.append(
                        "exec esp-coredump dbg_corefile -t raw --core {} \\\n"
                        "    --extra-gdbinit-file module_symbols.gdbinit {}".format(core_arc, elf_arc)
                    )
                else:
                    lines.append("exec esp-coredump dbg_corefile -t raw --core {} {}".format(core_arc, elf_arc))

                script = tempfile.NamedTemporaryFile(delete=False)
                script.write(("\n".join(lines) + "\n").encode())
                script.close()
                zip_file.write(script.name, arcname="crash_{}/elf_{}.sh".format(crash_id, elf_image["elf_file_id"]))
                os.unlink(script.name)
        finally:
            for m in loaded:
                try:
                    os.remove(m["elf"])
                except OSError:
                    pass
            if core_elf:
                try:
                    os.remove(core_elf)
                except OSError:
                    pass
            if prog_tmp:
                try:
                    os.remove(prog_tmp)
                except OSError:
                    pass
            try:
                os.remove(dmp.name)
            except OSError:
                pass

    # Send zip file
    status = send_file(zipf.name, mimetype='application/zip', as_attachment=True, download_name="crash_{}.zip".format(crash_id))
    os.unlink(zipf.name)
    return status


@login_required
def delete_crash(project_name, crash_id):
    """Delete a crash entry."""
    c = ldb().cursor()
    auth_where, auth_args = auth_project_in_clause("project_name")
    c.execute("DELETE FROM crash WHERE crash_id = %s AND " + auth_where, (crash_id,) + auth_args)
    ldb().commit()
    return redirect(f"/projects/{project_name}", code=302)


def register(app):
    app.add_url_rule('/crash/<crash_id>', endpoint="show_crash", view_func=show_crash)
    app.add_url_rule('/projects/<project_name>/<crash_id>', endpoint="show_project_crash", view_func=show_project_crash)
    app.add_url_rule('/projects/<project_name>/<crash_id>/refresh', endpoint="refresh_crash", view_func=refresh_crash)
    app.add_url_rule('/crash/<crash_id>/download', endpoint="download_crash", view_func=download_crash)
    app.add_url_rule('/projects/<project_name>/<crash_id>/delete', endpoint="delete_crash", view_func=delete_crash)
