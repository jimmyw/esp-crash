import os
import re

from functools import wraps
from flask import Flask, app, request, redirect, url_for, session, send_file
from flask_dance.contrib.github import make_github_blueprint, github
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg2
import subprocess
import tempfile
import bz2
import zipfile
import datetime
import requests

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

def get_data(cur, *args):
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

# Custom filter to format date and remove microseconds
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    return value.strftime(format)

app.jinja_env.filters['format_datetime'] = format_datetime


def render_template(template_name, **context):
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
    return app.jinja_env.get_template(template_name).render(projects=projects, **context)


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
    return render_template('index.html')

@app.route('/projects/<project_name>')
@login_required
def listProjectCrashes(project_name):
    search = request.args.get('search', None)
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))


    where_part = "project_auth.github = %s "
    args = (session["gh_user"],)
    if project_name:
        where_part += "AND crash.project_name = %s "
        args = args + (project_name,)
    if search and len(search) > 0:
        where_part += "AND textsearch @@ to_tsquery(%s) "
        args = args + (search,)
    args = args + (limit, offset,)

    crashes = ldb().get_data("""
        SELECT
            crash.crash_id,
            crash.date,
            crash.project_name,
            crash.device_id,
            crash.project_ver,
            array_agg(elf_file.elf_file_id) FILTER (WHERE elf_file.elf_file_id IS NOT NULL) as elf_file_id,
            array_agg(elf_file.project_alias) as project_alias,
            device.ext_device_id,
            device.alias,
            count(*) OVER() AS full_count
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        LEFT JOIN
            elf_file USING (project_name, project_ver)
        LEFT JOIN
            device USING (device_id)
        WHERE
        """ + where_part + """
        GROUP BY
            crash.crash_id,
            crash.date,
            crash.project_name,
            crash.device_id,
            crash.project_ver,
            device.ext_device_id,
            device.alias
        ORDER BY
            crash.date DESC, crash.crash_id
        LIMIT
            %s
        OFFSET
            %s
    """, args)



    return render_template('project.html', crashes = crashes, project_name = project_name, search = search or "", limit = limit, offset = offset, full_count = crashes[0]["full_count"] if len(crashes) > 0 else 0)

@app.route('/crash')
@login_required
def listCrashes():
    return listProjectCrashes(None)

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
    return redirect(url_for("listProjectCrashes", project_name = project_name), code=302)

@app.route('/projects/<project_name>/builds')
@login_required
def listBuilds(project_name):
    builds = ldb().get_data("""
        SELECT
            elf_file.elf_file_id,
            elf_file.date,
            elf_file.project_name,
            elf_file.project_ver,
            elf_file.project_alias,
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
    return redirect(url_for('project_settings', project_name=project_name))

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
    return redirect(url_for("project_settings", project_name = project_name), code=302)

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
    return redirect(url_for("project_settings", project_name = project_name), code=302)


@app.route('/projects/<project_name>/settings')
@login_required
def project_settings(project_name):
    db = ldb()
    # Verify user has access to this project
    allowed = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND github = %s
    """, (project_name, session.get("gh_user")))
    if not allowed:
        return "Forbidden: You do not have access to this project.", 403

    acls = db.get_data("""
        SELECT github, date, project_name
        FROM project_auth
        WHERE project_name = %s
        ORDER BY date DESC
    """, (project_name,))

    cur = db.cursor()
    cur.execute("SELECT webhook_id, webhook_url FROM project_webhooks WHERE project_name = %s ORDER BY webhook_id", (project_name,))
    webhooks_list = cur.fetchall()

    return render_template('project_settings.html', project_name=project_name, acls=acls, webhooks=webhooks_list)

@app.route('/projects/<project_name>/webhooks', methods=['GET', 'POST'])
@login_required
def project_webhooks_admin(project_name):
    db = ldb()
    cur = db.cursor()

    # Permission check: Ensure user is authorized for this project
    auth_check = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND github = %s
    """, (project_name, session.get("gh_user")))
    if not auth_check:
        return "Forbidden: You do not have access to this project's webhooks.", 403

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'add':
            webhook_url = request.form.get('webhook_url')
            if not webhook_url:
                # Consider flashing a message here instead of just returning an error
                return "Webhook URL cannot be empty.", 400

            # Check if webhook_url already exists for this project
            cur.execute("SELECT webhook_id FROM project_webhooks WHERE project_name = %s AND webhook_url = %s", (project_name, webhook_url))
            if cur.fetchone():
                # Optionally, flash a message: "Webhook URL already exists for this project."
                pass # Or return some error/message
            else:
                cur.execute("""
                    INSERT INTO project_webhooks (project_name, webhook_url)
                    VALUES (%s, %s)
                """, (project_name, webhook_url))
                db.commit()

        elif action == 'delete':
            webhook_id = request.form.get('webhook_id')
            if not webhook_id:
                return "Webhook ID is required for deletion.", 400

            # The permission check at the beginning covers project-level access.
            # Deleting by webhook_id and project_name ensures we only delete from the correct project.
            cur.execute("""
                DELETE FROM project_webhooks
                WHERE webhook_id = %s AND project_name = %s
            """, (webhook_id, project_name))
            db.commit()

        return redirect(url_for('project_settings', project_name=project_name))

    # GET request logic
    return redirect(url_for('project_settings', project_name=project_name))

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
    return show_project_crash(None, crash_id)

@app.route('/projects/<project_name>/<crash_id>')
@login_required
def show_project_crash(project_name, crash_id):

    # Fetch crash data from database
    crash = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, crash.device_id, crash.project_ver, crash.crash_dmp, device.ext_device_id, COALESCE(device.alias, '') as device_alias, crash.dump
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        JOIN
            device USING (device_id)
        WHERE
            crash_id = %s AND project_auth.github = %s
        ORDER BY
            date DESC""", (crash_id, session["gh_user"],))
    # If no crash data is found, return "Not found"
    if len(crash) != 1:
        return "Not found", 404

    crash = crash[0]

    # Fetch all elf image data from database that matches this project and version
    elf_images = ldb().get_data("SELECT elf_file_id, date, project_name, project_ver, elf_file, project_alias FROM elf_file WHERE project_name = %s AND project_ver = %s ORDER BY date DESC", (crash["project_name"], crash["project_ver"], ))

    return render_template('crash.html', crash = crash, elf_images = elf_images, dump = crash["dump"])


@app.route('/projects/<project_name>/<crash_id>/refresh')
@login_required
def refresh_crash(project_name, crash_id):

    # Fetch crash data from database
    refresh = """
        UPDATE
            crash
        SET
            dump = NULL
        FROM
            project_auth
        WHERE
            crash.crash_id = %s AND crash.project_name = project_auth.project_name AND project_auth.github = %s
        """

    c = ldb().cursor()
    c.execute(refresh, (crash_id, session["gh_user"],))
    conn.commit()

    return redirect(url_for('show_project_crash', project_name=project_name, crash_id=crash_id))


@app.route('/cron')
def cron():

    c = ldb().cursor()
    # Fetch all crashes from database that has not been processed
    crashes = ldb().get_data("""
        SELECT
            crash.crash_id, crash.date, crash.project_name, crash.project_ver, crash.crash_dmp
        FROM
            crash
        WHERE
            dump IS NULL AND
            (select count(e.elf_file_id) from elf_file as e where e.project_name = crash.project_name and e.project_ver = crash.project_ver) > 0
        ORDER BY
            crash.crash_id DESC
        LIMIT 10
        """)
    # If no crash data is found, return "Not found"
    if len(crashes) < 1:
        return "Nothing to do\n", 200

    app.logger.info("Processing {} crashes".format(len(crashes)))
    for crash in crashes:
        app.logger.info("Processing crash {} project_name '{}' date '{}'".format(crash["crash_id"], crash["project_name"], crash["date"]))

        # Fetch all elf image data from database that matches this project and version
        elf_images = ldb().get_data("SELECT elf_file_id, date, project_name, project_ver, elf_file FROM elf_file WHERE project_name = %s AND project_ver = %s ORDER BY date DESC", (crash["project_name"], crash["project_ver"], ))

        dump = ""
        if len(elf_images) < 1:
            app.logger.info("  No elf_file found")
            continue

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

        # Update the dump field in the database with the crash dump info

        c.execute("UPDATE crash SET dump = %s WHERE crash_id = %s", (dump, crash["crash_id"],))
        conn.commit()
        app.logger.info("Updated crash {}".format(crash["crash_id"]))

        # Send webhooks
        project_name = crash["project_name"]
        webhooks = ldb().get_data("SELECT webhook_url FROM project_webhooks WHERE project_name = %s", (project_name,))

        if webhooks:
            app.logger.info(f"Found {len(webhooks)} webhooks for project {project_name}")
            with app.app_context(): # Needed for url_for to work outside of a request context
                details_url = url_for('show_project_crash', project_name=crash["project_name"], crash_id=crash["crash_id"], _external=True)

            payload = {
                "project_name": crash["project_name"],
                "project_ver": crash["project_ver"],
                "crash_id": crash["crash_id"],
                "crash_dump_snippet": dump[:500],
                "details_url": details_url
            }
            headers = {
                'User-Agent': 'ESP-Crash-Webhook-Notifier/1.0',
                'Content-Type': 'application/json'
            }

            for webhook in webhooks:
                webhook_url = webhook["webhook_url"]
                try:
                    response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
                    response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
                    app.logger.info(f"Successfully sent webhook to {webhook_url} for crash {crash['crash_id']}")
                except requests.exceptions.RequestException as e:
                    app.logger.error(f"Failed to send webhook to {webhook_url} for crash {crash['crash_id']}: {e}")
        else:
            app.logger.info(f"No webhooks found for project {project_name}")


    # return just a 200 OK
    return "OK\n", 200

@app.route('/build/<build_id>/download')
@login_required
def download_build(build_id):

    # Fetch all elf image data from database that matches this project and version
    elf_images = ldb().get_data("""
    SELECT
        elf_file.elf_file_id, elf_file.date, elf_file.project_name, elf_file.project_ver, elf_file.elf_file
    FROM
        elf_file
    LEFT JOIN
        project_auth USING (project_name)
    WHERE
        elf_file_id = %s AND
        project_auth.github = %s

    """, (build_id, session["gh_user"],))

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


@app.route('/crash/<crash_id>/download')
@login_required
def download_crash(crash_id):

    # Fetch crash data from database
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


@app.route('/projects/<project_name>/<crash_id>/delete')
@login_required
@login_required
def delete_crash(project_name, crash_id):
    c = ldb().cursor()
    c.execute("DELETE FROM crash WHERE crash_id = %s AND project_name IN (SELECT project_name FROM project_auth WHERE github = %s)", (crash_id, session["gh_user"]))
    conn.commit()
    return redirect(f"/projects/{project_name}", code=302)


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

@app.route('/build/<build_id>')
@login_required
def showBuild(build_id):
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

@app.route('/device/<device_id>', methods = ['POST'])
@login_required
def updateDeviceAlias(device_id):
    # Extract the new alias from the POST data
    new_alias = request.form.get('alias')

    c = ldb().cursor()
    res = c.execute("""
        UPDATE device
        SET alias = %s
        WHERE device_id = %s
        RETURNING device_id
    """, (new_alias, device_id))
    conn.commit()
    print(res)
    return showDevice(device_id)

@app.route('/build/<build_id>', methods = ['POST'])
@login_required
def updateBuildAlias(build_id):
    # Extract the new alias from the POST data
    new_alias = request.form.get('alias')

    c = ldb().cursor()
    res = c.execute("""
        UPDATE elf_file
        SET project_alias = %s
        WHERE elf_file_id = %s
        RETURNING elf_file_id
    """, (new_alias, build_id))
    conn.commit()
    print(res)
    return showBuild(build_id)

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
    cursor.execute('INSERT INTO device (ext_device_id) VALUES (%s) ON CONFLICT (ext_device_id) DO UPDATE SET ext_device_id = EXCLUDED.ext_device_id RETURNING device_id', (arguments["DEVICE_ID"],))
    device_id = cursor.fetchone()[0]
    cursor.execute('INSERT INTO crash (date, project_name, project_ver, crash_dmp, device_id) VALUES (NOW(), %s, %s, %s, %s)',
    (arguments["PROJECT_NAME"], arguments["PROJECT_VER"], psycopg2.Binary(compressed_content), device_id))

    # Commit the changes and close the connection
    conn.commit()
    return "OK", 200

@app.route('/upload_elf', methods = ['POST'])
def upload_elf():
    # Connect to the database
    conn = ldb()

    # Check if the file is in the request
    if 'file' not in request.files:
        return "No file part", 500
    file = request.files['file']

    # Check if a file has been selected
    if file.filename == '':
        return "No selected file", 500

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

    if match and len(match.group(1)) > 2 and len(match.group(2)) > 2:
        project_name = match.group(1)
        project_ver = match.group(2)

    # Get the project name and version from the request arguments
    project_name = request.args.get('project_name', project_name)
    project_ver = request.args.get('project_ver', project_ver)

    project_name = request.form.get('project_name', project_name)
    project_ver = request.form.get('project_ver', project_ver)

    # Check if the project name and version are provided
    if not project_name:
        return "Missing project_name", 500
    if not project_ver:
        return "Missing project_ver", 500

    app.logger.info("Adding elf file")
    app.logger.info(f"Project name: '{project_name}'")
    app.logger.info(f"Project version: '{project_ver}'")


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
