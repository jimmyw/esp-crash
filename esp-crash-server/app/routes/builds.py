"""Build (uploaded ELF) detail, alias update, download, and delete.
Mechanical move from server.py - routes and logic unchanged, endpoint names
preserved exactly (registered directly on the app object, not via Flask
Blueprint - see core.py for why)."""
import os
import bz2
import tempfile
import zipfile

from flask import redirect, request, send_file, url_for
from sqlalchemy import delete, select, update

from ..auth import auth_filter, auth_project_in_filter, login_required
from ..models import ElfFile, ProjectAuth, db
from ..rendering import render_template


@login_required
def show_build(build_id):
    """Display details for a specific build."""
    #app.logger.info(build_id)
    builds = db.session.execute(
        select(
            ElfFile.elf_file_id.label("build_id"),
            ElfFile.project_name.label("build_name"),
            ElfFile.project_ver.label("build_ver"),
            ElfFile.project_alias.label("build_alias"),
        ).where(ElfFile.elf_file_id == build_id)
    ).mappings().all()
    if len(builds) == 1:
        return render_template('build.html', build = builds[0])
    return "Build not found", 400


@login_required
def update_build_alias(build_id):
    """Update the alias for a specific build."""
    # Extract the new alias from the POST data
    new_alias = request.form.get('alias')

    db.session.execute(
        update(ElfFile).where(ElfFile.elf_file_id == build_id).values(project_alias=new_alias)
    )
    db.session.commit()
    return show_build(build_id)


@login_required
def download_build(build_id):
    """Download ELF build data as a zip archive."""

    # Fetch all elf image data from database that matches this project and version
    elf_images = db.session.execute(
        select(
            ElfFile.elf_file_id, ElfFile.date, ElfFile.project_name,
            ElfFile.project_ver, ElfFile.elf_file,
        )
        .outerjoin(ProjectAuth, ElfFile.project_name == ProjectAuth.project_name)
        .where(ElfFile.elf_file_id == build_id, auth_filter(ProjectAuth.github))
    ).mappings().all()

    zipf = tempfile.NamedTemporaryFile(delete=False)
    with zipfile.ZipFile(zipf.name, 'w', zipfile.ZIP_DEFLATED) as zip_file:

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
            zip_file.write(elf.name, arcname="build_{}_{}/elf_{}.elf".format(elf_image["project_name"],elf_image["elf_file_id"], elf_image["elf_file_id"]))

            os.unlink(elf.name)

            script = tempfile.NamedTemporaryFile(delete=False)
            script.write("#!/bin/bash\n".encode())
            script.write(". $ESP_IDF/export.sh\n".encode())
            #script.write("exec esp-coredump dbg_corefile -t raw --core {} {}\n".format("crash_{}.dmp".format(elf_image["elf_file_id"]), "elf_{}.elf".format(elf_image["elf_file_id"])).encode())
            script.close()
            zip_file.write(script.name, arcname="build_{}_{}/elf_{}.sh".format(elf_image["project_name"],elf_image["elf_file_id"], elf_image["elf_file_id"]))

    # Send zip file
    status = send_file(zipf.name, mimetype='application/zip', as_attachment=True, download_name="build_{}_{}.zip".format(elf_image["project_name"],build_id,))
    os.unlink(zipf.name)
    return status


@login_required
def delete_elf(elf_file_id):
    # Select project_name from the deleted elf_file to redirect appropriately after delete
    af = auth_project_in_filter(ElfFile.project_name)
    project_data = db.session.execute(
        select(ElfFile.project_name).where(ElfFile.elf_file_id == elf_file_id, af)
    ).mappings().all()
    if len(project_data) < 1:
        return "Not found", 404
    project_name = project_data[0]["project_name"]

    """Delete an uploaded ELF build."""
    db.session.execute(
        delete(ElfFile).where(ElfFile.elf_file_id == elf_file_id, af)
    )
    db.session.commit()

    return redirect(url_for('list_builds', project_name=project_name), code=302)


def register(app):
    app.add_url_rule('/build/<build_id>', endpoint="show_build", view_func=show_build)
    app.add_url_rule('/build/<build_id>', endpoint="update_build_alias", view_func=update_build_alias, methods=['POST'])
    app.add_url_rule('/build/<build_id>/download', endpoint="download_build", view_func=download_build)
    app.add_url_rule('/elf/delete/<elf_file_id>', endpoint="delete_elf", view_func=delete_elf)
