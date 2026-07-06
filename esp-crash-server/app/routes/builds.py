"""Build (uploaded ELF) detail, alias update, download, and delete.
Mechanical move from server.py - routes and logic unchanged, endpoint names
preserved exactly (registered directly on the app object, not via Flask
Blueprint - see core.py for why)."""
import os
import bz2
import tempfile
import zipfile

from flask import redirect, request, send_file, url_for

from ..auth import auth_clause, auth_project_in_clause, login_required
from ..db import ldb
from ..rendering import render_template


@login_required
def show_build(build_id):
    """Display details for a specific build."""
    #app.logger.info(build_id)
    builds = ldb().get_data("""
        SELECT
            elf_file_id as build_id,
            project_name as build_name,
            project_ver as build_ver,
            project_alias as build_alias
        FROM
            elf_file
        WHERE
            elf_file_id = %s
    """, (build_id,))
    if len(builds) == 1:
        return render_template('build.html', build = builds[0])
    return "Build not found", 400


@login_required
def update_build_alias(build_id):
    """Update the alias for a specific build."""
    # Extract the new alias from the POST data
    new_alias = request.form.get('alias')

    c = ldb().cursor()
    res = c.execute("""
        UPDATE elf_file
        SET project_alias = %s
        WHERE elf_file_id = %s
        RETURNING elf_file_id
    """, (new_alias, build_id))
    ldb().commit()
    print(res)
    return show_build(build_id)


@login_required
def download_build(build_id):
    """Download ELF build data as a zip archive."""

    # Fetch all elf image data from database that matches this project and version
    auth_where, auth_args = auth_clause("project_auth.github")
    elf_images = ldb().get_data("""
    SELECT
        elf_file.elf_file_id, elf_file.date, elf_file.project_name, elf_file.project_ver, elf_file.elf_file
    FROM
        elf_file
    LEFT JOIN
        project_auth USING (project_name)
    WHERE
        elf_file_id = %s AND
        """ + auth_where + """

    """, (build_id,) + auth_args)

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
    auth_where, auth_args = auth_project_in_clause("project_name")
    project_data = ldb().get_data("SELECT project_name FROM elf_file WHERE elf_file_id = %s AND " + auth_where, (elf_file_id,) + auth_args)
    if len(project_data) < 1:
        return "Not found", 404
    project_name = project_data[0]["project_name"]

    """Delete an uploaded ELF build."""
    c = ldb().cursor()
    c.execute("DELETE FROM elf_file WHERE elf_file_id = %s AND " + auth_where, (elf_file_id,) + auth_args)
    ldb().commit()

    return redirect(url_for('list_builds', project_name=project_name), code=302)


def register(app):
    app.add_url_rule('/build/<build_id>', endpoint="show_build", view_func=show_build)
    app.add_url_rule('/build/<build_id>', endpoint="update_build_alias", view_func=update_build_alias, methods=['POST'])
    app.add_url_rule('/build/<build_id>/download', endpoint="download_build", view_func=download_build)
    app.add_url_rule('/elf/delete/<elf_file_id>', endpoint="delete_elf", view_func=delete_elf)
