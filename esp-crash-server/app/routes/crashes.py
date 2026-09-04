"""Crash detail, refresh, delete, and download. Mechanical move from
server.py - routes and logic unchanged, endpoint names preserved exactly
(registered directly on the app object, not via Flask Blueprint - see
core.py for why)."""
import os
import re
import bz2
import tempfile
import zipfile

from flask import current_app, redirect, send_file, url_for

import toolchains
from sqlalchemy import delete, func, select, update

# The zip is built from stored data now; no decoder needed here.
from ..auth import auth_filter, auth_project_in_filter, login_required
from ..models import Crash, CrashRelation, CrashRelationTag, Device, ElfFile, ModuleElf, ProjectAuth, ProjectSettings, Tag, db
from ..rendering import render_template


@login_required
def show_crash(crash_id):
    """Redirect to crash details, inferring the project name."""
    return show_project_crash(None, crash_id)


@login_required
def show_project_crash(project_name, crash_id):
    """Display crash details for a project."""

    # Fetch crash data from database
    crash = db.session.execute(
        select(
            Crash.crash_id, Crash.date, Crash.project_name, Crash.device_id,
            Crash.project_ver, Crash.crash_dmp, Device.ext_device_id,
            func.coalesce(Device.alias, "").label("device_alias"), Crash.dump,
            ProjectSettings.device_url_template, ProjectSettings.toolchain,
            Crash.module_map,
            CrashRelation.ai_title, CrashRelation.ai_summary, Crash.signature,
        )
        .select_from(Crash)
        .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
        .join(Device, Crash.device_id == Device.device_id)
        .outerjoin(ProjectSettings, Crash.project_name == ProjectSettings.project_name)
        # Outer: a crash with no signature has no relation - it simply
        # shows no title/summary (see the crash.ai_title/ai_summary guards
        # in crash.html).
        .outerjoin(CrashRelation, (CrashRelation.project_name == Crash.project_name) & (CrashRelation.signature == Crash.signature))
        .where(Crash.crash_id == crash_id, auth_filter(ProjectAuth.github))
        .order_by(Crash.date.desc())
    ).mappings().all()
    # If no crash data is found, return "Not found"
    if len(crash) != 1:
        return "Not found", 404

    crash = dict(crash[0])

    # Fetch all elf image data from database that matches this project and version
    elf_images = db.session.execute(
        select(
            ElfFile.elf_file_id, ElfFile.date, ElfFile.project_name,
            ElfFile.project_ver, ElfFile.file_size, ElfFile.project_alias,
        )
        .where(ElfFile.project_name == crash["project_name"], ElfFile.project_ver == crash["project_ver"])
        .order_by(ElfFile.date.desc())
    ).mappings().all()

    # Tags live on the crash's relation (project_name, signature) - a
    # crash with no signature has no relation and so no tags.
    crash["tags"] = db.session.execute(
        select(Tag.tag_id, Tag.name, Tag.description)
        .join(CrashRelationTag, CrashRelationTag.tag_id == Tag.tag_id)
        .where(
            CrashRelationTag.project_name == crash["project_name"],
            CrashRelationTag.signature == crash["signature"],
        )
        .order_by(Tag.name)
    ).mappings().all() if crash["signature"] else []

    # Full project tag list, for the "pick an existing tag" datalist.
    project_tags = db.session.execute(
        select(Tag.name, Tag.description)
        .where(Tag.project_name == crash["project_name"])
        .order_by(Tag.name)
    ).mappings().all()

    # Module tags come from the persisted module_map (written at cron time).
    # Availability is computed live because a module ELF may be uploaded after
    # the crash was processed.
    modules_for_ui = []
    for e in (crash.get("module_map") or []):
        sha1 = e.get("sha1", "")
        row = db.session.execute(
            select(ModuleElf.module_elf_id).where(ModuleElf.app_sha1 == sha1).limit(1)
        ).first()
        modules_for_ui.append({
            "name": e.get("name", ""),
            "version": e.get("version", ""),
            "sha1_short": sha1[:8],
            "sha1_full": sha1,
            "available": bool(row),
        })

    # Offer the Debug link only when a session could actually start: the
    # project must name an installed toolchain, the debug service must be
    # configured, and there must be a build to load symbols from. Showing a
    # link that always fails is worse than showing none.
    debug_available = bool(
        crash.get("toolchain")
        and crash["toolchain"] in toolchains.installed()
        and current_app.config.get("GDB_PUBLIC_WS_URL")
        and current_app.config.get("GDB_TICKET_SECRET")
        and elf_images
    )

    return render_template('crash.html', crash = crash, elf_images = elf_images, dump = crash["dump"], modules = modules_for_ui, project_tags = project_tags, debug_available = debug_available)


@login_required
def refresh_crash(project_name, crash_id):
    """Clear cached dump data so it will be reprocessed."""

    # Clear dump only when a matching project_auth row exists (original used
    # UPDATE ... FROM project_auth, so an absent grant left the row untouched).
    db.session.execute(
        update(Crash)
        .where(
            Crash.crash_id == crash_id,
            Crash.project_name.in_(
                select(ProjectAuth.project_name).where(auth_filter(ProjectAuth.github))
            ),
        )
        .values(dump=None)
    )
    db.session.commit()

    return redirect(url_for('show_project_crash', project_name=project_name, crash_id=crash_id))


@login_required
def reload_crash_summary(project_name, crash_id):
    """Clear the stored AI title/summary on this crash's relation so the
    next cron tick regenerates them - affects every crash sharing this
    signature, since the review is owned by the whole group (see
    app/ai_tagging.py), not this crash alone. Existing tags are left alone
    - summarize_and_tag never removes a tag, only adds ones that fit.
    No-op if the crash has no signature (no relation) or the caller lacks
    access."""
    signature = db.session.execute(
        select(Crash.signature)
        .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
        .where(
            Crash.crash_id == crash_id,
            Crash.project_name == project_name,
            auth_filter(ProjectAuth.github),
        )
    ).scalar_one_or_none()
    if signature:
        db.session.execute(
            update(CrashRelation)
            .where(CrashRelation.project_name == project_name, CrashRelation.signature == signature)
            .values(ai_title=None, ai_summary=None)
        )
        db.session.commit()

    return redirect(url_for('show_project_crash', project_name=project_name, crash_id=crash_id))


@login_required
def download_crash(crash_id):
    """Download a crash dump along with related ELF files."""

    # Fetch crash data from database
    crash = db.session.execute(
        select(
            Crash.crash_id, Crash.date, Crash.project_name, Device.ext_device_id,
            Crash.project_ver, Crash.crash_dmp, Crash.module_map,
        )
        .select_from(Crash)
        .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
        .join(Device, Crash.device_id == Device.device_id)
        .where(Crash.crash_id == crash_id, auth_filter(ProjectAuth.github))
        .order_by(Crash.date.desc())
    ).mappings().all()
    # If no crash data is found, return "Not found"
    if len(crash) != 1:
        return "Not found", 404

    crash = crash[0]

    # Fetch all elf image data from database that matches this project and version
    elf_images = db.session.execute(
        select(
            ElfFile.elf_file_id, ElfFile.date, ElfFile.project_name,
            ElfFile.project_ver, ElfFile.elf_file,
        )
        .where(ElfFile.project_name == crash["project_name"], ElfFile.project_ver == crash["project_ver"])
        .order_by(ElfFile.date.desc())
    ).mappings().all()

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

        # Module symbols come from the crash's stored module_map, which records
        # each module's sha1 and section addresses at decode time. Reading the
        # registry here would mean running a debugger, and decoding now happens
        # inside the sandboxed debug service - so a plain file download must not
        # depend on either.
        module_map = crash.get("module_map") or []
        # Crashes decoded before section addresses were recorded have the names
        # but not the placement, and there is no way to reconstruct it without
        # the core. Those get the module ELFs and an explanation rather than a
        # gdbinit; re-running "Regenerate crash" produces a complete package.
        placed = [m for m in module_map if m.get("text") is not None]
        unplaced = [m for m in module_map if m.get("text") is None]
        try:
            gdbinit_lines = []
            missing = []
            for m in placed:
                blob = db.session.execute(
                    select(ModuleElf.elf_file).where(ModuleElf.app_sha1 == m["sha1"]).limit(1)
                ).scalars().first()
                if blob is None:
                    missing.append("# module {} (sha1 {}...): symbols not available".format(
                        m["name"], (m.get("sha1") or "")[:8]))
                    continue
                try:
                    module_elf = bz2.decompress(bytes(blob))
                except IOError:
                    module_elf = bytes(blob)
                safe = re.sub(r'[^A-Za-z0-9._-]', '_', m["name"])
                arc = "modules/{}.elf".format(safe)
                zip_file.writestr("crash_{}/{}".format(crash_id, arc), module_elf)
                gdbinit_lines.append(
                    "add-symbol-file {arc} {text:#x} -s .data {data:#x} "
                    "-s .bss {bss:#x} -s .rodata {rodata:#x}".format(
                        arc=arc, text=m["text"], data=m["data"],
                        bss=m["bss"], rodata=m["rodata"])
                )
            if gdbinit_lines:
                zip_file.writestr(
                    "crash_{}/module_symbols.gdbinit".format(crash_id),
                    "# Literal add-symbol-file lines for this crash's modules.\n"
                    "# Run gdb from this directory so the relative module paths\n"
                    "# resolve. No gdb-Python required.\n"
                    + "\n".join(gdbinit_lines) + "\n",
                )
            if unplaced:
                missing.append(
                    "# This crash was decoded before module section addresses were "
                    "recorded, so no\n# add-symbol-file lines could be generated for: "
                    + ", ".join(m["name"] for m in unplaced)
                    + ".\n# Press \"Regenerate crash\" on the crash page to produce a "
                      "complete package.")
            if missing:
                zip_file.writestr(
                    "crash_{}/MODULES_README.txt".format(crash_id),
                    "Notes on this crash's runtime modules:\n\n"
                    + "\n".join(missing) + "\n",
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
            # Module ELFs are written into the archive from memory now, and no
            # core file or program ELF is extracted at all, so the only
            # temporary left to clean is the decompressed dump.
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
    db.session.execute(
        delete(Crash).where(
            Crash.crash_id == crash_id,
            auth_project_in_filter(Crash.project_name),
        )
    )
    db.session.commit()
    return redirect(f"/projects/{project_name}", code=302)


@login_required
def debug_crash(project_name, crash_id):
    """The interactive debug terminal page.

    Renders the xterm.js console only; it fetches its own session ticket from
    /api/v1/crashes/<id>/gdb-session and connects to the separate debug
    service. Access is enforced there and again by that service, so this view
    deliberately does no ACL query of its own beyond login_required - it hands
    out no crash data.
    """
    return render_template('gdb.html', project_name=project_name, crash_id=crash_id)


def register(app):
    app.add_url_rule('/crash/<crash_id>', endpoint="show_crash", view_func=show_crash)
    app.add_url_rule('/projects/<project_name>/<crash_id>', endpoint="show_project_crash", view_func=show_project_crash)
    app.add_url_rule('/projects/<project_name>/<crash_id>/refresh', endpoint="refresh_crash", view_func=refresh_crash)
    app.add_url_rule('/projects/<project_name>/<crash_id>/reload-summary', endpoint="reload_crash_summary", view_func=reload_crash_summary, methods=['POST'])
    app.add_url_rule('/crash/<crash_id>/download', endpoint="download_crash", view_func=download_crash)
    app.add_url_rule('/projects/<project_name>/<crash_id>/delete', endpoint="delete_crash", view_func=delete_crash)
    # <int:> here, unlike the older sibling routes: this is a new route and
    # the API path it talks to is /api/v1/crashes/<int:crash_id>, so a
    # non-numeric id is rejected at routing rather than reaching the view.
    app.add_url_rule('/projects/<project_name>/<int:crash_id>/debug', endpoint="debug_crash", view_func=debug_crash)
