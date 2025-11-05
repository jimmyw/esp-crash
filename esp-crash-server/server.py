import os
import re
import json

from functools import wraps
from flask import Flask, app, request, redirect, url_for, session, send_file, jsonify
from flask_dance.contrib.github import make_github_blueprint, github
from werkzeug.middleware.proxy_fix import ProxyFix
import psycopg2
import subprocess
import tempfile
import bz2
import zipfile
import datetime
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class DBManager:
    def __init__(self, database='example', host="db", user="root", password_file=None):
        pf = open(password_file, 'r')
        logger.info("Connecting to database %s at %s as user %s", database, host, user)
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
        logger.info("Executing query: %s args: %s", args[0], args[1:])
        cur.execute(*args)
        result = cur.fetchall()
        column_names = [desc[0] for desc in cur.description]
        return [dict(zip(column_names, row)) for row in result]

#def get_data(cur, *args):
#    logger.info("Executing query: %s", args[0])
#    cur.execute(*args)
#    result = cur.fetchall()
#    column_names = [desc[0] for desc in cur.description]
#    return [dict(zip(column_names, row)) for row in result]


app = Flask(__name__)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

app.secret_key = os.environ["APP_SECRET_KEY"]
app.config['MAX_CONTENT_LENGTH'] = 64 * 1000 * 1000
app.config["GITHUB_OAUTH_CLIENT_ID"] = os.environ["GITHUB_OAUTH_CLIENT_ID"]
app.config["GITHUB_OAUTH_CLIENT_SECRET"] = os.environ["GITHUB_OAUTH_CLIENT_SECRET"]
app.config["SLACK_CLIENT_ID"] = os.environ.get("SLACK_CLIENT_ID", "")
app.config["SLACK_CLIENT_SECRET"] = os.environ.get("SLACK_CLIENT_SECRET", "")

# External URL configuration for Slack notifications
app.config["EXTERNAL_URL"] = os.environ.get("EXTERNAL_URL", "")
if not app.config["EXTERNAL_URL"]:
    app.logger.warning("EXTERNAL_URL not set - Slack URLs may not work properly")

conn = None

# Custom filter to format date and remove microseconds
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    return value.strftime(format)

app.jinja_env.filters['format_datetime'] = format_datetime

def external_url_for(endpoint, **values):
    """Generate external URL for Slack notifications."""
    external_url = app.config.get("EXTERNAL_URL")
    if external_url:
        # Remove trailing slash from external URL
        external_url = external_url.rstrip('/')
        # Generate the path using url_for
        with app.app_context():
            path = url_for(endpoint, **values)
        return f"{external_url}{path}"
    else:
        # Fallback to regular url_for with _external=True
        with app.app_context():
            return url_for(endpoint, _external=True, **values)


def render_template(template_name, **context):
    """Render a template with project list context."""
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
    """Decorator to require GitHub authentication."""
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
    """Lazy-initialize and return the database connection."""
    global conn
    if not conn:
        conn = DBManager(password_file='/run/secrets/db-password', host='192.168.10.92', user='esp-crash', database='esp-crash')
    return conn;

@app.route("/dashboard")
@login_required
def dashboard():
    """Render the user dashboard."""
    return render_template('dashboard.html')

@app.route("/settings")
@login_required
def settings():
    """Render the account settings page."""
    return render_template('settings.html')

@app.route('/')
@login_required
def list_projects():
    """Render the landing page listing all projects."""
    return render_template('index.html')

@app.route('/projects/<project_name>')
@login_required
def list_project_crashes(project_name):
    """List crashes for a given project name."""
    search = request.args.get('search', None)
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))


    where_part = "project_auth.github = %s "
    args = (session["gh_user"],)
    if project_name:
        where_part += "AND crash.project_name = %s "
        args = args + (project_name,)
    if search and len(search) > 0:
        # Clean and format for to_tsquery
        sanitized_search = re.sub(r'[^\w\s]', ' ', search)
        # Split by whitespace, filter empty strings, and join with &
        terms = [term.strip() for term in sanitized_search.split() if term.strip()]
        if terms:
            tsquery_string = ' & '.join(terms)
            where_part += "AND textsearch @@ to_tsquery(%s) "
            args = args + (tsquery_string,)
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
def list_crashes():
    """List the most recent crashes across all projects."""
    return list_project_crashes(None)

@app.route('/projects/create', methods = ['POST'])
@login_required
def create_project():
    """Create a new project for the authenticated user."""

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
    return redirect(url_for("list_project_crashes", project_name=project_name), code=302)

@app.route('/projects/<project_name>/builds')
@login_required
def list_builds(project_name):
    """List available build files for a project."""
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))

    builds = ldb().get_data("""
        SELECT
            elf_file.elf_file_id,
            elf_file.date,
            elf_file.project_name,
            elf_file.project_ver,
            elf_file.project_alias,
            length(elf_file.elf_file) AS size,
            COUNT(crash) AS crash_count,
            count(elf_file) OVER() AS full_count

        FROM
            elf_file
        JOIN
            project_auth USING (project_name)
        LEFT JOIN
            crash USING (project_name, project_ver)
        WHERE
            elf_file.project_name = %s AND
            project_auth.github = %s
        GROUP BY
            elf_file.elf_file_id,
            elf_file.date,
            elf_file.project_name,
            elf_file.project_ver,
            elf_file.project_alias
        ORDER BY date DESC
        LIMIT
            %s
        OFFSET
            %s

    """, (project_name, session["gh_user"], limit, offset))
    return render_template('builds.html', elfs = builds, project_name = project_name, limit=limit, offset=offset,  full_count = builds[0]["full_count"] if len(builds) > 0 else 0)

@app.route('/projects/<project_name>/acl')
@login_required
def list_acl(project_name):
    """Redirect to project access control settings."""
    return redirect(url_for('project_settings', project_name=project_name))

@app.route('/projects/<project_name>/acl/create', methods=['POST'])
@login_required
def create_acl(project_name):
    """Add a GitHub user to a project's access list."""
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
def delete_acl(project_name, github):
    """Remove a GitHub user from a project's access list."""
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
    """Display and manage settings for a specific project."""
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

    # Get Slack integrations
    slack_integrations = db.get_data("""
        SELECT slack_integration_id, slack_team_id, slack_team_name, slack_channel_id, slack_channel_name, created_date
        FROM project_slack_integrations
        WHERE project_name = %s
        ORDER BY created_date DESC
    """, (project_name,))

    return render_template('project_settings.html',
                         project_name=project_name,
                         acls=acls,
                         webhooks=webhooks_list,
                         slack_integrations=slack_integrations,
                         slack_client_id=app.config['SLACK_CLIENT_ID'])

@app.route('/projects/<project_name>/webhooks', methods=['GET', 'POST'])
@login_required
def project_webhooks_admin(project_name):
    """Manage webhooks for a project."""
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

@app.route('/projects/<project_name>/slack/auth')
@login_required
def slack_auth(project_name):
    """Initiate Slack OAuth flow for a project."""
    db = ldb()

    # Permission check: Ensure user is authorized for this project
    auth_check = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND github = %s
    """, (project_name, session.get("gh_user")))
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    # Store project_name in session for callback
    session['slack_auth_project'] = project_name

    # Redirect to Slack OAuth
    slack_oauth_url = (
        f"https://slack.com/oauth/v2/authorize?"
        f"client_id={app.config['SLACK_CLIENT_ID']}&"
        f"scope=chat:write,channels:read,groups:read,channels:join&"
        f"redirect_uri={url_for('slack_callback', _external=True)}"
    )
    return redirect(slack_oauth_url)

@app.route('/slack/callback')
@login_required
def slack_callback():
    """Handle Slack OAuth callback."""
    code = request.args.get('code')
    error = request.args.get('error')

    if error:
        return f"Slack authorization failed: {error}", 400

    if not code:
        return "Missing authorization code from Slack", 400

    project_name = session.get('slack_auth_project')
    if not project_name:
        return "Missing project information. Please try again.", 400

    try:
        # Exchange code for access token
        response = requests.post('https://slack.com/api/oauth.v2.access', data={
            'client_id': app.config['SLACK_CLIENT_ID'],
            'client_secret': app.config['SLACK_CLIENT_SECRET'],
            'code': code,
            'redirect_uri': url_for('slack_callback', _external=True)
        })

        slack_response = response.json()

        if not slack_response.get('ok'):
            return f"Slack API error: {slack_response.get('error', 'Unknown error')}", 400

        access_token = slack_response['access_token']
        team_id = slack_response['team']['id']
        team_name = slack_response['team']['name']

        # Store OAuth data in session for channel selection
        session['slack_oauth_data'] = {
            'access_token': access_token,
            'team_id': team_id,
            'team_name': team_name,
            'project_name': project_name
        }

        # Redirect to channel selection page
        return redirect(url_for('slack_channel_selection', project_name=project_name))

    except Exception as e:
        app.logger.error(f"Slack OAuth error: {e}")
        return f"Failed to complete Slack integration: {str(e)}", 500

@app.route('/slack/interactive', methods=['POST'])
def handle_slack_interactivity():
    """Handle Slack interactive component events."""
    try:
        # Slack sends the payload as form data
        payload = json.loads(request.form.get('payload', '{}'))

        # Log the interaction for debugging
        app.logger.info(f"Slack interaction received: {payload.get('type', 'unknown')}")

        if payload.get('type') == 'block_actions':
            # Handle button clicks
            action = payload['actions'][0] if payload.get('actions') else {}
            action_id = action.get('action_id', '')

            app.logger.info(f"Button clicked: {action_id}")

            # For URL buttons, just return empty response and let Slack handle the URL redirect
            if action_id in ['view_crash_details', 'view_project_settings']:
                # Return empty 200 response - this tells Slack to proceed with the URL
                return '', 200

        # For any other interaction types, just acknowledge
        return '', 200

    except Exception as e:
        app.logger.error(f"Slack interactivity error: {e}")
        # Always return 200 to avoid Slack retries
        return '', 200

@app.route('/projects/<project_name>/slack/channel-selection')
@login_required
def slack_channel_selection(project_name):
    """Show channel selection page after successful OAuth."""
    oauth_data = session.get('slack_oauth_data')
    if not oauth_data or oauth_data.get('project_name') != project_name:
        return "Session expired or invalid. Please try adding Slack integration again.", 400

    # Permission check
    db = ldb()
    auth_check = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND github = %s
    """, (project_name, session.get("gh_user")))
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    try:
        slack_client = WebClient(token=oauth_data['access_token'])

        # Get public channels
        channels_response = slack_client.conversations_list(
            types="public_channel,private_channel",
            exclude_archived=True,
            limit=200
        )

        if not channels_response['ok']:
            return f"Failed to fetch channels: {channels_response.get('error', 'Unknown error')}", 400

        channels = []
        for channel in channels_response['channels']:
            if channel.get('is_member', False) or not channel.get('is_private', False):
                channels.append({
                    'id': channel['id'],
                    'name': channel['name'],
                    'is_private': channel.get('is_private', False),
                    'purpose': channel.get('purpose', {}).get('value', '')[:100]
                })

        # Sort channels by name
        channels.sort(key=lambda x: x['name'])

        return render_template('slack_channel_selection.html',
                             project_name=project_name,
                             team_name=oauth_data['team_name'],
                             channels=channels)

    except Exception as e:
        app.logger.error(f"Channel selection error: {e}")
        return f"Failed to load channels: {str(e)}", 500

@app.route('/projects/<project_name>/slack/channel-selection', methods=['POST'])
@login_required
def slack_channel_selection_post(project_name):
    """Process channel selection and save integration."""
    oauth_data = session.get('slack_oauth_data')
    if not oauth_data or oauth_data.get('project_name') != project_name:
        return "Session expired or invalid. Please try adding Slack integration again.", 400

    selected_channel_id = request.form.get('channel_id')
    selected_channel_name = request.form.get('channel_name')

    if not selected_channel_id or not selected_channel_name:
        return "Please select a channel.", 400

    try:
        # Store Slack integration in database
        db = ldb()
        cur = db.cursor()

        # Check if integration already exists for this team
        existing = db.get_data("""
            SELECT slack_integration_id FROM project_slack_integrations
            WHERE project_name = %s AND slack_team_id = %s
        """, (project_name, oauth_data['team_id']))

        if existing:
            # Update existing integration
            cur.execute("""
                UPDATE project_slack_integrations
                SET slack_access_token = %s, slack_team_name = %s, slack_channel_id = %s, slack_channel_name = %s
                WHERE project_name = %s AND slack_team_id = %s
            """, (oauth_data['access_token'], oauth_data['team_name'], selected_channel_id, selected_channel_name,
                  project_name, oauth_data['team_id']))
        else:
            # Create new integration
            cur.execute("""
                INSERT INTO project_slack_integrations
                (project_name, slack_team_id, slack_team_name, slack_channel_id, slack_channel_name, slack_access_token, github_user)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (project_name, oauth_data['team_id'], oauth_data['team_name'], selected_channel_id, selected_channel_name,
                  oauth_data['access_token'], session.get("gh_user")))

        db.commit()

        # Clean up session
        session.pop('slack_oauth_data', None)
        session.pop('slack_auth_project', None)

        return redirect(url_for('project_settings', project_name=project_name))

    except Exception as e:
        app.logger.error(f"Failed to save Slack integration: {e}")
        return f"Failed to save integration: {str(e)}", 500

@app.route('/projects/<project_name>/slack/<int:integration_id>/delete')
@login_required
def delete_slack_integration(project_name, integration_id):
    """Delete a Slack integration."""
    db = ldb()
    cur = db.cursor()

    # Permission check and delete
    cur.execute("""
        DELETE FROM project_slack_integrations
        WHERE slack_integration_id = %s
        AND project_name = %s
        AND project_name IN (SELECT project_name FROM project_auth WHERE github = %s)
    """, (integration_id, project_name, session.get("gh_user")))

    db.commit()
    return redirect(url_for('project_settings', project_name=project_name))

@app.route('/projects/<project_name>/slack/<int:integration_id>/update_channel', methods=['POST'])
@login_required
def update_slack_channel(project_name, integration_id):
    """Update Slack channel for an integration."""
    channel_id = request.form.get('channel_id')
    channel_name = request.form.get('channel_name')

    if not channel_id or not channel_name:
        return "Missing channel information", 400

    db = ldb()
    cur = db.cursor()

    # Update channel information
    cur.execute("""
        UPDATE project_slack_integrations
        SET slack_channel_id = %s, slack_channel_name = %s
        WHERE slack_integration_id = %s
        AND project_name = %s
        AND project_name IN (SELECT project_name FROM project_auth WHERE github = %s)
    """, (channel_id, channel_name, integration_id, project_name, session.get("gh_user")))

    db.commit()
    return redirect(url_for('project_settings', project_name=project_name))

@app.route('/elf/delete/<elf_file_id>')
@login_required
def delete_elf(elf_file_id):
    """Delete an uploaded ELF build."""
    c = ldb().cursor()
    c.execute("DELETE FROM elf_file WHERE elf_file_id = %s AND project_name IN (SELECT project_name FROM project_auth WHERE github = %s)", (elf_file_id, session["gh_user"]))
    conn.commit()
    return redirect("/elf", code=302)

@app.route('/crash/<crash_id>')
@login_required
def show_crash(crash_id):
    """Redirect to crash details, inferring the project name."""
    return show_project_crash(None, crash_id)

@app.route('/projects/<project_name>/<crash_id>')
@login_required
def show_project_crash(project_name, crash_id):
    """Display crash details for a project."""

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
    """Clear cached dump data so it will be reprocessed."""

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
    """Process pending crash dumps and send webhooks."""

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
            details_url = external_url_for('show_project_crash', project_name=crash["project_name"], crash_id=crash["crash_id"])

            app.logger.info(f"Generated details URL for crash {crash['crash_id']}: {details_url}")

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

        # Send Slack notifications
        slack_integrations = ldb().get_data("""
            SELECT slack_access_token, slack_channel_id, slack_channel_name
            FROM project_slack_integrations
            WHERE project_name = %s
        """, (project_name,))

        if slack_integrations:
            app.logger.info(f"Found {len(slack_integrations)} Slack integrations for project {project_name}")
            details_url = external_url_for('show_project_crash', project_name=crash["project_name"], crash_id=crash["crash_id"])

            app.logger.info(f"Generated Slack details URL for crash {crash['crash_id']}: {details_url}")

            for integration in slack_integrations:
                try:
                    slack_client = WebClient(token=integration["slack_access_token"])

                    # Create Slack message
                    blocks = [
                        {
                            "type": "header",
                            "text": {
                                "type": "plain_text",
                                "text": "🚨 ESP Crash Detected"
                            }
                        },
                        {
                            "type": "section",
                            "fields": [
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Project:* {crash['project_name']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Version:* {crash['project_ver']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Crash ID:* {crash['crash_id']}"
                                },
                                {
                                    "type": "mrkdwn",
                                    "text": f"*Channel:* #{integration['slack_channel_name']}"
                                }
                            ]
                        }
                    ]

                    # Add crash dump snippet if available
                    if dump and len(dump.strip()) > 0:
                        crash_snippet = dump[:1000]
                        if len(dump) > 1000:
                            crash_snippet += "..."

                        blocks.append({
                            "type": "section",
                            "text": {
                                "type": "mrkdwn",
                                "text": f"*Crash Dump (first 1000 chars):*\n```{crash_snippet}```"
                            }
                        })

                    # Add action button
                    blocks.append({
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "View Details"
                                },
                                "url": details_url,
                                "action_id": "view_crash_details"
                            }
                        ]
                    })

                    response = slack_client.chat_postMessage(
                        channel=integration["slack_channel_id"],
                        blocks=blocks,
                        text=f"ESP Crash detected in {crash['project_name']} (v{crash['project_ver']})"
                    )

                    if response["ok"]:
                        app.logger.info(f"Successfully sent Slack notification to #{integration['slack_channel_name']} for crash {crash['crash_id']}")
                    else:
                        error_msg = response.get('error', 'Unknown error')
                        if error_msg == 'not_in_channel':
                            # Try to join the channel automatically (only works for public channels)
                            try:
                                join_response = slack_client.conversations_join(channel=integration["slack_channel_id"])
                                if join_response["ok"]:
                                    # Successfully joined, now try to send the message again
                                    retry_response = slack_client.chat_postMessage(
                                        channel=integration["slack_channel_id"],
                                        blocks=blocks,
                                        text=f"ESP Crash detected in {crash['project_name']} (v{crash['project_ver']})"
                                    )
                                    if retry_response["ok"]:
                                        app.logger.info(f"Auto-joined #{integration['slack_channel_name']} and sent crash notification for crash {crash['crash_id']}")
                                    else:
                                        app.logger.error(f"Joined #{integration['slack_channel_name']} but failed to send crash notification: {retry_response.get('error', 'Unknown error')}")
                                else:
                                    app.logger.error(f"Bot not in channel #{integration['slack_channel_name']} and could not auto-join for crash {crash['crash_id']}. Please invite the bot manually.")
                            except Exception as join_error:
                                app.logger.error(f"Bot not in channel #{integration['slack_channel_name']} and auto-join failed for crash {crash['crash_id']}: {join_error}")
                        else:
                            app.logger.error(f"Slack API returned error for #{integration['slack_channel_name']} crash {crash['crash_id']}: {error_msg}")

                except SlackApiError as e:
                    app.logger.error(f"Failed to send Slack notification to #{integration['slack_channel_name']} for crash {crash['crash_id']}: {e}")
                except Exception as e:
                    app.logger.error(f"Unexpected error sending Slack notification for crash {crash['crash_id']}: {e}")
        else:
            app.logger.info(f"No Slack integrations found for project {project_name}")


    # return just a 200 OK
    return "OK\n", 200

@app.route('/build/<build_id>/download')
@login_required
def download_build(build_id):
    """Download ELF build data as a zip archive."""

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
    """Download a crash dump along with related ELF files."""

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
    """Delete a crash entry."""
    c = ldb().cursor()
    c.execute("DELETE FROM crash WHERE crash_id = %s AND project_name IN (SELECT project_name FROM project_auth WHERE github = %s)", (crash_id, session["gh_user"]))
    conn.commit()
    return redirect(f"/projects/{project_name}", code=302)


@app.route('/device/<device_id>')
@login_required
def show_device(device_id):
    """Display details for a specific device."""
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

@app.route('/device/<device_id>', methods=['POST'])
@login_required
def update_device_alias(device_id):
    """Update the user-defined alias for a device."""
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
    return show_device(device_id)

@app.route('/build/<build_id>', methods=['POST'])
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
    conn.commit()
    print(res)
    return show_build(build_id)

@app.route('/dump', methods = ['POST'])
def dump():
    """Upload a crash dump from a device."""
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


    # Rate limiting: Check if device has uploaded more than 5 crashes in the last hour
    cursor.execute('''
        SELECT COUNT(*)
        FROM crash
        JOIN device USING (device_id)
        WHERE ext_device_id = %s
        AND date >= NOW() - INTERVAL '1 hour'
    ''', (arguments["DEVICE_ID"],))
    crash_count = cursor.fetchone()[0]

    if crash_count >= 5:
        return "Rate limit exceeded: Maximum 5 crashes per device per hour", 429

    cursor.execute('INSERT INTO device (ext_device_id) VALUES (%s) ON CONFLICT (ext_device_id) DO UPDATE SET ext_device_id = EXCLUDED.ext_device_id RETURNING device_id', (arguments["DEVICE_ID"],))
    device_id = cursor.fetchone()[0]
    cursor.execute('INSERT INTO crash (date, project_name, project_ver, crash_dmp, device_id) VALUES (NOW(), %s, %s, %s, %s)',
    (arguments["PROJECT_NAME"], arguments["PROJECT_VER"], psycopg2.Binary(compressed_content), device_id))

    # Commit the changes and close the connection
    conn.commit()
    return "OK", 200

@app.route('/upload_elf', methods = ['POST'])
def upload_elf():
    """Upload an ELF file containing build information."""
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

@app.route('/projects/<project_name>/slack/test')
@login_required
def test_slack_integration(project_name):
    """Test Slack integration by sending a test message."""
    db = ldb()

    # Permission check
    auth_check = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND github = %s
    """, (project_name, session.get("gh_user")))
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    # Get Slack integrations
    slack_integrations = db.get_data("""
        SELECT slack_access_token, slack_channel_id, slack_channel_name, slack_team_id, slack_team_name
        FROM project_slack_integrations
        WHERE project_name = %s
    """, (project_name,))

    if not slack_integrations:
        return "No Slack integrations found for this project.", 404

    results = []
    debug_info = []
    test_url = external_url_for('project_settings', project_name=project_name)

    app.logger.info(f"Generated test URL: {test_url}")

    for integration in slack_integrations:
        channel_name = integration['slack_channel_name']
        channel_id = integration['slack_channel_id']
        team_name = integration.get('slack_team_name', 'Unknown')

        debug_info.append(f"Testing integration for team: {team_name}, channel: #{channel_name} (ID: {channel_id})")

        try:
            slack_client = WebClient(token=integration["slack_access_token"])

            # First, let's check if we can access channel info
            try:
                channel_info = slack_client.conversations_info(channel=channel_id)
                if channel_info["ok"]:
                    debug_info.append(f"✅ Channel info retrieved successfully for #{channel_name}")
                    debug_info.append(f"   - Channel exists: {channel_info['channel']['name']}")
                    debug_info.append(f"   - Is member: {channel_info['channel'].get('is_member', 'Unknown')}")
                else:
                    debug_info.append(f"❌ Failed to get channel info: {channel_info.get('error', 'Unknown error')}")
            except Exception as info_error:
                debug_info.append(f"❌ Error getting channel info: {info_error}")

            # Now try to send the message
            debug_info.append(f"Attempting to send message to #{channel_name}...")

            response = slack_client.chat_postMessage(
                channel=channel_id,
                blocks=[
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": "🧪 ESP-Crash Test Message"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"This is a test message from ESP-Crash for project *{project_name}*.\n\nIf you see this message, the Slack integration is working correctly!\n\n*Debug Info:*\n• Team: {team_name}\n• Channel: #{channel_name}\n• Channel ID: {channel_id}\n• Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        }
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": {
                                    "type": "plain_text",
                                    "text": "Project Settings"
                                },
                                "url": test_url,
                                "action_id": "view_project_settings"
                            }
                        ]
                    }
                ],
                text=f"ESP-Crash test message for {project_name}"
            )

            # Log the full response for debugging
            debug_info.append(f"Slack API Response: {response}")

            if response["ok"]:
                message_ts = response.get('ts', 'Unknown')
                workspace_name = integration.get('slack_team_name', 'Unknown')
                results.append(f"✅ Successfully sent test message to #{channel_name} in '{workspace_name}' workspace (message timestamp: {message_ts})")
                debug_info.append(f"✅ Message sent successfully with timestamp: {message_ts}")
            else:
                error_msg = response.get('error', 'Unknown error')
                if error_msg == 'not_in_channel':
                    # Try to join the channel automatically (only works for public channels)
                    try:
                        join_response = slack_client.conversations_join(channel=integration["slack_channel_id"])
                        if join_response["ok"]:
                            # Successfully joined, now try to send the message again
                            retry_response = slack_client.chat_postMessage(
                                channel=integration["slack_channel_id"],
                                blocks=[
                                    {
                                        "type": "header",
                                        "text": {
                                            "type": "plain_text",
                                            "text": "🧪 ESP-Crash Test Message"
                                        }
                                    },
                                    {
                                        "type": "section",
                                        "text": {
                                            "type": "mrkdwn",
                                            "text": f"This is a test message from ESP-Crash for project *{project_name}*.\n\nThe bot automatically joined this channel and sent this test message!"
                                        }
                                    },
                                    {
                                        "type": "actions",
                                        "elements": [
                                            {
                                                "type": "button",
                                                "text": {
                                                    "type": "plain_text",
                                                    "text": "Project Settings"
                                                },
                                                "url": test_url,
                                                "action_id": "view_project_settings"
                                            }
                                        ]
                                    }
                                ],
                                text=f"ESP-Crash test message for {project_name}"
                            )
                            if retry_response["ok"]:
                                results.append(f"✅ Auto-joined #{integration['slack_channel_name']} and sent test message successfully")
                            else:
                                results.append(f"⚠️ Joined #{integration['slack_channel_name']} but failed to send message: {retry_response.get('error', 'Unknown error')}")
                        else:
                            # Could not join (probably a private channel)
                            results.append(f"❌ Bot not in channel #{integration['slack_channel_name']}: Please invite the ESP-Crash bot to this channel first. Go to the channel and type: <code>/invite @ESP-Crash</code>")
                    except Exception as join_error:
                        results.append(f"❌ Bot not in channel #{integration['slack_channel_name']}: Could not auto-join. Please invite the bot manually: <code>/invite @ESP-Crash</code>")
                elif error_msg == 'channel_not_found':
                    results.append(f"❌ Channel #{integration['slack_channel_name']} not found: The channel may have been deleted or renamed")
                elif error_msg == 'invalid_auth' or error_msg == 'token_revoked':
                    results.append(f"❌ Authentication failed for #{integration['slack_channel_name']}: Please reconnect the Slack integration")
                else:
                    results.append(f"❌ Failed to send to #{integration['slack_channel_name']}: {error_msg}")

        except SlackApiError as e:
            error_msg = str(e)
            if 'not_in_channel' in error_msg:
                results.append(f"❌ Bot not in channel #{integration['slack_channel_name']}: Please invite the ESP-Crash bot to this channel first. Go to the channel and type: <code>/invite @ESP-Crash</code>")
            elif 'channel_not_found' in error_msg:
                results.append(f"❌ Channel #{integration['slack_channel_name']} not found: The channel may have been deleted or renamed")
            elif 'invalid_auth' in error_msg or 'token_revoked' in error_msg:
                results.append(f"❌ Authentication failed for #{integration['slack_channel_name']}: Please reconnect the Slack integration")
            else:
                results.append(f"❌ Slack API error for #{integration['slack_channel_name']}: {e}")
        except Exception as e:
            results.append(f"❌ Unexpected error for #{integration['slack_channel_name']}: {e}")

    # Check for success and "not_in_channel" patterns
    has_success = any('✅' in result for result in results)
    has_not_in_channel = any('not_in_channel' in result for result in results)

    return render_template('slack_test_results.html',
                           project_name=project_name,
                           results=results,
                           debug_info=debug_info,
                           has_success=has_success,
                           has_not_in_channel=has_not_in_channel)

@app.route('/projects/<project_name>/slack/verify')
@login_required
def verify_slack_integration(project_name):
    """Verify Slack integration settings and permissions."""
    db = ldb()

    # Permission check
    auth_check = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND github = %s
    """, (project_name, session.get("gh_user")))
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    # Get Slack integrations with enhanced info
    slack_integrations = db.get_data("""
        SELECT slack_integration_id, slack_access_token, slack_channel_id, slack_channel_name, slack_team_name, slack_team_id
        FROM project_slack_integrations
        WHERE project_name = %s
    """, (project_name,))

    if not slack_integrations:
        return render_template('slack_verification.html',
                               project_name=project_name,
                               integrations=[],
                               verification_results=["No Slack integrations found for this project."])

    verification_results = []
    db_info = []

    # Prepare integration data with validation status
    integrations_with_status = []

    for integration in slack_integrations:
        integration_data = {
            'id': integration['slack_integration_id'],
            'team_name': integration.get('slack_team_name', 'Unknown Team'),
            'channel_name': integration['slack_channel_name'],
            'channel_id': integration['slack_channel_id'],
            'bot_valid': False
        }

        verification_results.append(f"Verifying integration for {integration.get('slack_team_name', 'Unknown Team')}")

        try:
            slack_client = WebClient(token=integration["slack_access_token"])

            # Test auth
            auth_test = slack_client.auth_test()
            if auth_test["ok"]:
                integration_data['bot_valid'] = True
                verification_results.append(f"✅ Auth test passed")
                verification_results.append(f"   Bot User ID: {auth_test.get('user_id', 'Unknown')}")
                verification_results.append(f"   Team: {auth_test.get('team', 'Unknown')}")
                verification_results.append(f"   User: {auth_test.get('user', 'Unknown')}")

                db_info.append(f"Integration ID: {integration['slack_integration_id']}")
                db_info.append(f"Team ID: {integration.get('slack_team_id', 'Unknown')}")
                db_info.append(f"Channel ID: {integration['slack_channel_id']}")
                db_info.append(f"Token: {integration['slack_access_token'][:10]}...")
            else:
                verification_results.append(f"❌ Auth test failed: {auth_test.get('error', 'Unknown')}")
                continue

            # Check channel info
            channel_info = slack_client.conversations_info(channel=integration["slack_channel_id"])
            if channel_info["ok"]:
                channel = channel_info["channel"]
                verification_results.append(f"✅ Channel info retrieved")
                verification_results.append(f"   Channel Name: #{channel.get('name', 'Unknown')}")
                verification_results.append(f"   Channel ID: {channel.get('id', 'Unknown')}")
                verification_results.append(f"   Is Member: {channel.get('is_member', False)}")
                verification_results.append(f"   Is Private: {channel.get('is_private', False)}")
                verification_results.append(f"   Is Archived: {channel.get('is_archived', False)}")
            else:
                verification_results.append(f"❌ Channel info failed: {channel_info.get('error', 'Unknown')}")

        except Exception as e:
            verification_results.append(f"❌ Verification error: {e}")

        integrations_with_status.append(integration_data)

    return render_template('slack_verification.html',
                           project_name=project_name,
                           integrations=integrations_with_status,
                           verification_results=verification_results,
                           db_info=db_info)

if __name__ == '__main__':
    app.run()
