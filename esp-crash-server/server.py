import os
import re

from functools import wraps
from flask import Flask, app, request, render_template, redirect, url_for, session, send_file
from flask_dance.contrib.github import make_github_blueprint, github
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg2
import subprocess
import tempfile
import bz2
import zipfile


class DBManager:
    def __init__(self, database='example', host="db", user="root", password_file=None):
        pf = open(password_file, 'r')
        self.connection = psycopg2.connect(
            user=user,
            password=pf.read(),
            host=host,
            database=database
        )
        pf.close()

    def cursor(self):
        self.connection.rollback()
        return self.connection.cursor()

    def commit(self):
        return self.connection.commit()

    def get_data(self, *args):
        cur = self.cursor()
        cur.execute(*args)
        result = cur.fetchall()
        column_names = [desc[0] for desc in cur.description]
        return [dict(zip(column_names, row)) for row in result]

app = Flask(__name__)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

app.secret_key = os.environ["APP_SECRET_KEY"]
app.config['MAX_CONTENT_LENGTH'] = 64 * 1000 * 1000
app.config["GITHUB_OAUTH_CLIENT_ID"] = os.environ["GITHUB_OAUTH_CLIENT_ID"]
app.config["GITHUB_OAUTH_CLIENT_SECRET"] = os.environ["GITHUB_OAUTH_CLIENT_SECRET"]
conn = None

github_bp = make_github_blueprint()
app.register_blueprint(github_bp, url_prefix="/login")
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not github.authorized:
            return redirect(url_for("github.login"))
        if "gh_user" not in session:
            resp = github.get("/user")
            if not resp.ok:
                return "Fail to auth github oauth", 500
            session["gh_user"] = resp.json()["login"]
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def handle_chunking():
    """
    Sets the "wsgi.input_terminated" environment flag, thus enabling
    Werkzeug to pass chunked requests as streams.  The gunicorn server
    should set this, but it's not yet been implemented.
    """

    transfer_encoding = request.headers.get("Transfer-Encoding", None)
    if transfer_encoding == u"chunked":
        request.environ["wsgi.input_terminated"] = True

def ldb():
    global conn
    if not conn:
        conn = DBManager(password_file='/run/secrets/db-password', host='192.168.10.92', user='esp-crash', database='esp-crash')
    return conn;

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route("/settings")
@login_required
def settings():
    return render_template('settings.html')

@app.route('/')
@login_required
def listProjects():
    projects = ldb().get_data("""
        SELECT
            project_name,
            (SELECT COUNT(crash_id) FROM crash WHERE crash.project_name = project_auth.project_name) AS crash_count
        FROM
            project_auth
        WHERE
            project_auth.github = %s
        ORDER BY
            project_name ASC
    """, (session["gh_user"],))
    return render_template('index.html', projects = projects)

@app.route('/projects/<project_name>')
@login_required
def listProject(project_name):
    crashes = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, crash.ext_device_id,
            crash.project_ver, elf_file.elf_file_id, elf_file.date as elf_date,
            device.device_id, device.alias
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        LEFT JOIN
            elf_file USING (project_name, project_ver)
        LEFT JOIN
            device USING (ext_device_id)
        WHERE
            crash.project_name = %s AND
            project_auth.github = %s
        ORDER BY
            crash.date DESC
    """, (project_name, session["gh_user"],))
    return render_template('project.html', crashes = crashes, project_name = project_name)

@app.route('/crash')
@login_required
def listCrashes():
    crashes = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, crash.ext_device_id,
            crash.project_ver, elf_file.elf_file_id, elf_file.date as elf_date
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        LEFT JOIN
            elf_file USING (project_name, project_ver)
        WHERE
            project_auth.github = %s
        ORDER BY
            crash.date DESC
    """, (session["gh_user"],))
    return render_template('project.html', crashes = crashes, )



@app.route('/projects/create', methods = ['POST'])
@login_required
def createProject():

    project_name = request.form['project_name']
    if len(project_name) < 1:
        return "Missing project_name", 400
    c = ldb().cursor()

    projects = ldb().get_data("""
        SELECT
            project_name
        FROM
            project_auth
        WHERE
            project_name = %s AND
            project_auth.github = %s
    """, (project_name, session["gh_user"],))
    if len(projects) > 0:
        return "Project already registred, ask admin for invite", 400
    c.execute("""
        INSERT INTO
            project_auth
            ("date" , project_name, github)
        VALUES
            (NOW(), %s, %s)

        """, (project_name, session["gh_user"]))
    conn.commit()
    return redirect(url_for("listProject", project_name = project_name), code=302)

@app.route('/projects/<project_name>/builds')
@login_required
def listBuilds(project_name):
    builds = ldb().get_data("""
        SELECT
            elf_file.elf_file_id,
            elf_file.date,
            elf_file.project_name,
            elf_file.project_ver,
            length(elf_file.elf_file) AS size,
            (SELECT COUNT(crash_id) FROM crash WHERE crash.project_name = elf_file.project_name AND crash.project_ver = elf_file.project_ver) AS crash_count
        FROM
            elf_file
        JOIN
            project_auth USING (project_name)
        WHERE
            elf_file.project_name = %s AND
            project_auth.github = %s
        ORDER BY date DESC
    """, (project_name, session["gh_user"],))
    return render_template('builds.html', elfs = builds, project_name = project_name)

@app.route('/projects/<project_name>/acl')
@login_required
def listACL(project_name):
    acls = ldb().get_data("""
        SELECT
            github,
            date,
            project_name
        FROM
            project_auth
        WHERE
            project_name IN (SELECT project_name FROM project_auth WHERE github = %s) AND
            project_name = %s
        ORDER BY date DESC
    """, (session["gh_user"], project_name,))
    return render_template('acl.html', acls = acls, project_name = project_name)

@app.route('/projects/<project_name>/acl/create', methods = ['POST'])
@login_required
def createACL(project_name):
    c = ldb().cursor()
    acls = ldb().get_data("""
        SELECT
            project_name
        FROM
            project_auth
        WHERE
            project_name IN (SELECT project_name FROM project_auth WHERE github = %s) AND
            project_name = %s
        LIMIT 1
    """, (session["gh_user"], project_name,))

    if len(acls) < 1:
        return "No access to create for this project", 500
    github = request.form['github']
    if len(github) < 1:
        return "Missing github name", 400

    acls = ldb().get_data("""
        SELECT
            github
        FROM
            project_auth
        WHERE
            project_name = %s AND
            github = %s
    """, (project_name, github,))

    if len(acls) > 0:
        return "User already exists", 400

    c.execute("""
        INSERT INTO
            project_auth
            ("date" , project_name, github)
        VALUES
            (NOW(), %s, %s)

        """, (project_name, github))
    conn.commit()
    return redirect(url_for("listACL", project_name = project_name), code=302)

@app.route('/projects/<project_name>/acl/delete/<github>')
@login_required
def deleteACL(project_name, github):
    c = ldb().cursor()
    c.execute("""
        DELETE FROM
            project_auth
        WHERE
            github = %s AND
            project_name = %s AND
            project_name IN (SELECT project_name FROM project_auth WHERE github = %s)
    """, (github, project_name, session["gh_user"]))
    conn.commit()
    return redirect(url_for("listACL", project_name = project_name), code=302)

@app.route('/elf/delete/<elf_file_id>')
@login_required
def deleteElf(elf_file_id):
    c = ldb().cursor()
    c.execute("DELETE FROM elf_file WHERE elf_file_id = %s AND project_name IN (SELECT project_name FROM project_auth WHERE github = %s)", (elf_file_id, session["gh_user"]))
    conn.commit()
    return redirect("/elf", code=302)

@app.route('/crash/<crash_id>')
@login_required
def show_crash(crash_id):

    # Fetch crash data from database
    crash = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, crash.ext_device_id, crash.project_ver, crash.crash_dmp
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        WHERE
            crash_id = %s AND project_auth.github = %s
        ORDER BY
            date DESC""", (crash_id, session["gh_user"],))
    # If no crash data is found, return "Not found"
    if len(crash) != 1:
        return "Not found", 404

    crash = crash[0]

    # Fetch all elf image data from database that matches this project and version
    elf_images = ldb().get_data("SELECT elf_file_id, date, project_name, project_ver, elf_file FROM elf_file WHERE project_name = %s AND project_ver = %s ORDER BY date DESC", (crash["project_name"], crash["project_ver"], ))

    dump = ""
    if len(elf_images) < 1:
        dump = "No elf_file found"

    for elf_image in elf_images:
        # Create temporary files to store crash and elf data
        dmp = tempfile.NamedTemporaryFile(delete=False)
        elf = tempfile.NamedTemporaryFile(delete=False)

        # Decompress crash_dmp and elf_file before writing to temp files
        try:
            decompressed_crash_dmp = bz2.decompress(crash["crash_dmp"])
        except IOError:
            decompressed_crash_dmp = crash["crash_dmp"]
        try:
            decompressed_elf_file = bz2.decompress(elf_image["elf_file"])
        except IOError:
            decompressed_elf_file = elf_image["elf_file"]

        # Write decompressed data to temporary files
        dmp.write(decompressed_crash_dmp)
        dmp.close()
        elf.write(decompressed_elf_file)
        elf.close()

        # Run esp-coredump to get crash dump info
        p = subprocess.run(["esp-coredump", "--chip", "esp32s3", "info_corefile", "-t", "raw", "-c", dmp.name, elf.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        d = p.stdout + p.stderr
        dump += d.decode("utf-8")

        # Delete temporary files
        os.unlink(dmp.name)
        os.unlink(elf.name)


    return render_template('crash.html', crash = crash, elf_images = elf_images, dump = dump)

@app.route('/crash/<crash_id>/download')
@login_required
def download_crash(crash_id):

    # Fetch crash data from database
    crash = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, crash.ext_device_id, crash.project_ver, crash.crash_dmp
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        WHERE
            crash_id = %s AND project_auth.github = %s
        ORDER BY
            date DESC""", (crash_id, session["gh_user"],))
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
        os.unlink(dmp.name)

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

            script = tempfile.NamedTemporaryFile(delete=False)
            script.write("#!/bin/bash\n".encode())
            script.write(". $ESP_IDF/export.sh\n".encode())
            script.write("exec esp-coredump dbg_corefile -t raw --core {} {}\n".format("crash_{}.dmp".format(crash_id), "elf_{}.elf".format(elf_image["elf_file_id"])).encode())
            script.close()
            zip_file.write(script.name, arcname="crash_{}/elf_{}.sh".format(crash_id, elf_image["elf_file_id"]))




    # Send zip file
    status = send_file(zipf.name, mimetype='application/zip', as_attachment=True, download_name="crash_{}.zip".format(crash_id))
    os.unlink(zipf.name)
    return status


@app.route('/crash/delete/<crash_id>')
@login_required
def delete_crash(crash_id):
    c = ldb().cursor()
    c.execute("DELETE FROM crash WHERE crash_id = %s AND project_name IN (SELECT project_name FROM project_auth WHERE github = %s)", (crash_id, session["gh_user"]))
    conn.commit()
    return redirect("/", code=302)


@app.route('/device/<device_id>')
@login_required
def showDevice(device_id):
    #app.logger.info(device_id)
    devices = ldb().get_data("""
        SELECT
            device_id,
            ext_device_id,
            alias
        FROM
            device
        WHERE
            device_id = %s
    """, (device_id,))
    if len(devices) == 1:
        return render_template('device.html', device = devices[0])
    return "Device not found", 400

@app.route('/dump', methods = ['POST'])
def dump():
    # Connect to the database
    conn = ldb()

    # Check if a file is included in the request
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']

    # Check if a file has been selected
    if file.filename == '':
        return "No selected file", 400

    # Read the content of the file
    file_content = file.read()

    # Try to decompress the file content, if it's already compressed, use as is
    try:
        decompressed_content = bz2.decompress(file_content)
        compressed_content = file_content
    # If the file content is not compressed, compress it
    except OSError:
        decompressed_content = file_content
        compressed_content = bz2.compress(file_content)

    # Decode the file content
    decoded_content = decompressed_content.decode('utf-8', errors='ignore')

    # Use regex to find matches for the pattern in the decoded content
    # EXAMPLE LINE: ESP_CRASH:ecu-hub-esp32;1722-a2b84e59-dirty;68b6b341a58c;
    # EXAMPLE LINE: ESP_CRASH:test-firmware;1.55;aaa-bbb;
    pattern = r'ESP_CRASH:(.*?);(.*?);(.*?);'
    match = re.search(pattern, decoded_content)

    if not match:
        return "Missing ESP_CRASH identifier", 400

    arguments = {"PROJECT_NAME": match.group(1), "PROJECT_VER": match.group(2), "DEVICE_ID": match.group(3)}

    if not "PROJECT_NAME" in arguments:
        return "Missing or invalid project identifier", 400

    if not "PROJECT_VER" in arguments:
        return "Missing or invalid version identifier", 400

    if not "DEVICE_ID" in arguments:
        return "Missing or invalid device identifier", 400

    # Execute the SQL query to insert the compressed content into the database
    cursor = conn.cursor()
    cursor.execute('INSERT INTO crash (date, project_name, ext_device_id, project_ver, crash_dmp) VALUES (NOW(), %s, %s, %s, %s)',
    (arguments["PROJECT_NAME"], arguments["DEVICE_ID"], arguments["PROJECT_VER"], psycopg2.Binary(compressed_content),))

    # Commit the changes and close the connection
    conn.commit()
    return "OK", 200

@app.route('/upload_elf', methods = ['POST'])
def upload_elf():
    # Connect to the database
    conn = ldb()

    # Check if the file is in the request
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']

    # Check if a file has been selected
    if file.filename == '':
        return "No selected file", 400

    # Read the content of the file
    file_content = file.read()
    project_name = None
    project_ver = None

    # Try to decompress the file content to check if it is already compressed
    try:
        # If it is already compressed, use it as it is
        uncompressed_content = bz2.decompress(file_content)
        compressed_content = file_content
    except IOError:
        # If it is not compressed, compress the file content using bz2
        uncompressed_content = file_content
        compressed_content = bz2.compress(file_content)

    # Decode the file content
    decoded_content = uncompressed_content.decode('utf-8', errors='ignore')

    # Use regex to find matches for the pattern in the decoded content
    # EXAMPLE LINE: ESP_CRASH:ecu-hub-esp32;1722-a2b84e59-dirty;68b6b341a58c;
    # EXAMPLE LINE: ESP_CRASH:test-firmware;1.55;aaa-bbb;
    pattern = r'ESP_CRASH:(.*?);(.*?);(.*?);'
    match = re.search(pattern, decoded_content)

    if match:
        project_name = match.group(1)
        project_ver = match.group(2)

    # Get the project name and version from the request arguments
    project_name = request.args.get('project_name', project_name)
    project_ver = request.args.get('project_ver', project_ver)

    # Check if the project name and version are provided
    if not project_name:
        return "Missing project_name", 400
    if not project_ver:
        return "Missing project_ver", 400

    # Execute the SQL query to insert the compressed file content into the database
    cursor = conn.cursor()
    cursor.execute('INSERT INTO elf_file (date, project_name, project_ver, elf_file) VALUES (NOW(), %s, %s, %s)',
    (project_name, project_ver, psycopg2.Binary(compressed_content),))

    # Commit the changes and close the connection
    conn.commit()

    # Return a success message
    return "OK", 200

if __name__ == '__main__':
    app.run()
