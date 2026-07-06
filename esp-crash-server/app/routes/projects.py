"""Project listing, creation, crash listing, builds listing, ACL, and
per-project settings/webhooks/device-url admin. Mechanical move from
server.py - routes and logic unchanged, endpoint names preserved exactly
(registered directly on the app object, not via Flask Blueprint - see
core.py for why)."""
from flask import current_app, redirect, request, session, url_for

from device_url import DEVICE_ID_PLACEHOLDER, device_url_template_is_valid

from ..auth import auth_clause, login_required
from ..db import ldb
from ..rendering import render_template


@login_required
def list_project_crashes(project_name):
    """List crashes for a given project name."""
    search = request.args.get('search', None)
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))

    where_part, args = auth_clause("project_auth.github")
    where_part += " "
    if project_name:
        where_part += "AND crash.project_name = %s "
        args = args + (project_name,)
    if search and len(search) > 0:
        where_part += "AND textsearch @@ plainto_tsquery(%s) "
        args = args + (search,)
    args = args + (limit, offset,)

    crashes = ldb().get_data("""
        SELECT
            crash.crash_id,
            crash.date,
            crash.project_name,
            crash.device_id,
            crash.project_ver,
            crash.module_names,
            array_agg(elf_file.elf_file_id) FILTER (WHERE elf_file.elf_file_id IS NOT NULL) as elf_file_id,
            array_agg(elf_file.project_alias) as project_alias,
            device.ext_device_id,
            device.alias,
            project_settings.device_url_template,
            count(*) OVER() AS full_count
        FROM
            crash
        JOIN
            project_auth USING (project_name)
        LEFT JOIN
            elf_file USING (project_name, project_ver)
        LEFT JOIN
            device USING (device_id)
        LEFT JOIN
            project_settings USING (project_name)
        WHERE
        """ + where_part + """
        GROUP BY
            crash.crash_id,
            crash.date,
            crash.project_name,
            crash.device_id,
            crash.project_ver,
            device.ext_device_id,
            device.alias,
            project_settings.device_url_template
        ORDER BY
            crash.date DESC, crash.crash_id
        LIMIT
            %s
        OFFSET
            %s
    """, args)

    # crash.module_names is populated at cron processing time, so no per-row
    # coredump parsing happens here.
    return render_template('project.html', crashes = crashes, project_name = project_name, search = search or "", limit = limit, offset = offset, full_count = crashes[0]["full_count"] if len(crashes) > 0 else 0)


@login_required
def list_crashes():
    """List the most recent crashes across all projects."""
    return list_project_crashes(None)


@login_required
def create_project():
    """Create a new project for the authenticated user."""

    project_name = request.form['project_name']
    if len(project_name) < 1:
        return "Missing project_name", 400
    c = ldb().cursor()

    auth_where, auth_args = auth_clause("project_auth.github")
    projects = ldb().get_data("""
        SELECT
            project_name
        FROM
            project_auth
        WHERE
            project_name = %s AND
            """ + auth_where + """
    """, (project_name,) + auth_args)
    if len(projects) > 0:
        return "Project already registred, ask admin for invite", 400
    c.execute("""
        INSERT INTO
            project_auth
            ("date" , project_name, github)
        VALUES
            (NOW(), %s, %s)

        """, (project_name, session["gh_user"]))
    ldb().commit()
    return redirect(url_for("list_project_crashes", project_name=project_name), code=302)


@login_required
def list_builds(project_name):
    """List available build files for a project."""
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))

    auth_where, auth_args = auth_clause("project_auth.github")
    builds = ldb().get_data("""
        SELECT
            elf_file.elf_file_id,
            elf_file.date,
            elf_file.project_name,
            elf_file.project_ver,
            elf_file.project_alias,
            elf_file.file_size,
            COALESCE(crash_counts.crash_count, 0) AS crash_count,
            count(*) OVER() AS full_count
        FROM
            elf_file
        JOIN
            project_auth USING (project_name)
        LEFT JOIN LATERAL (
            SELECT COUNT(*) as crash_count
            FROM crash
            WHERE crash.project_name = elf_file.project_name
            AND crash.project_ver = elf_file.project_ver
        ) crash_counts ON true
        WHERE
            elf_file.project_name = %s AND
            """ + auth_where + """
        ORDER BY elf_file.date DESC
        LIMIT %s
        OFFSET %s

    """, (project_name,) + auth_args + (limit, offset))
    return render_template('builds.html', elfs = builds, project_name = project_name, limit=limit, offset=offset,  full_count = builds[0]["full_count"] if len(builds) > 0 else 0)


@login_required
def list_acl(project_name):
    """Redirect to project access control settings."""
    return redirect(url_for('project_settings', project_name=project_name))


@login_required
def create_acl(project_name):
    """Add a GitHub user to a project's access list."""
    c = ldb().cursor()
    auth_where, auth_args = auth_clause("github")
    acls = ldb().get_data("""
        SELECT
            project_name
        FROM
            project_auth
        WHERE
            """ + auth_where + """ AND
            project_name = %s
        LIMIT 1
    """, auth_args + (project_name,))

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
    ldb().commit()
    return redirect(url_for("project_settings", project_name = project_name), code=302)


@login_required
def delete_acl(project_name, github):
    """Remove a GitHub user from a project's access list."""
    c = ldb().cursor()
    auth_where, auth_args = auth_clause("github")
    c.execute("""
        DELETE FROM
            project_auth
        WHERE
            github = %s AND
            project_name = %s AND
            """ + auth_where + """
    """, (github, project_name) + auth_args)
    ldb().commit()
    return redirect(url_for("project_settings", project_name = project_name), code=302)


@login_required
def project_settings(project_name):
    """Display and manage settings for a specific project."""
    db = ldb()
    # Verify user has access to this project
    auth_where, auth_args = auth_clause("github")
    allowed = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND """ + auth_where + """
    """, (project_name,) + auth_args)
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

    settings_row = db.get_data(
        "SELECT device_url_template FROM project_settings WHERE project_name = %s",
        (project_name,))
    device_url_template = settings_row[0]['device_url_template'] if settings_row else ''

    return render_template('project_settings.html',
                         project_name=project_name,
                         acls=acls,
                         webhooks=webhooks_list,
                         slack_integrations=slack_integrations,
                         slack_client_id=current_app.config['SLACK_CLIENT_ID'],
                         device_url_template=device_url_template or '',
                         device_url_placeholder=DEVICE_ID_PLACEHOLDER,
                         device_url_error=request.args.get('device_url_error'))


@login_required
def project_webhooks_admin(project_name):
    """Manage webhooks for a project."""
    db = ldb()
    cur = db.cursor()

    # Permission check: Ensure user is authorized for this project
    auth_where, auth_args = auth_clause("github")
    auth_check = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND """ + auth_where + """
    """, (project_name,) + auth_args)
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


@login_required
def project_device_url_admin(project_name):
    """Save (or clear) the per-project device-id URL template."""
    db = ldb()
    cur = db.cursor()

    # Permission check: same gate as the rest of the project settings.
    auth_where, auth_args = auth_clause("github")
    auth_check = db.get_data("""
        SELECT project_name FROM project_auth
        WHERE project_name = %s AND """ + auth_where + """
    """, (project_name,) + auth_args)
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    template = (request.form.get('device_url_template') or '').strip()

    # A non-blank template must contain the {device_id} placeholder; blank clears it.
    if not device_url_template_is_valid(template):
        return redirect(url_for('project_settings', project_name=project_name, device_url_error='1'))

    cur.execute("""
        INSERT INTO project_settings (project_name, device_url_template)
        VALUES (%s, %s)
        ON CONFLICT (project_name) DO UPDATE SET device_url_template = EXCLUDED.device_url_template
    """, (project_name, template or None))
    db.commit()

    return redirect(url_for('project_settings', project_name=project_name))


def register(app):
    app.add_url_rule('/projects/<project_name>', endpoint="list_project_crashes", view_func=list_project_crashes)
    app.add_url_rule('/crash', endpoint="list_crashes", view_func=list_crashes)
    app.add_url_rule('/projects/create', endpoint="create_project", view_func=create_project, methods=['POST'])
    app.add_url_rule('/projects/<project_name>/builds', endpoint="list_builds", view_func=list_builds)
    app.add_url_rule('/projects/<project_name>/acl', endpoint="list_acl", view_func=list_acl)
    app.add_url_rule('/projects/<project_name>/acl/create', endpoint="create_acl", view_func=create_acl, methods=['POST'])
    app.add_url_rule('/projects/<project_name>/acl/delete/<github>', endpoint="delete_acl", view_func=delete_acl)
    app.add_url_rule('/projects/<project_name>/settings', endpoint="project_settings", view_func=project_settings)
    app.add_url_rule('/projects/<project_name>/webhooks', endpoint="project_webhooks_admin", view_func=project_webhooks_admin, methods=['GET', 'POST'])
    app.add_url_rule('/projects/<project_name>/settings/device-url', endpoint="project_device_url_admin", view_func=project_device_url_admin, methods=['POST'])
