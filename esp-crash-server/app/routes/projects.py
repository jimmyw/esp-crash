"""Project listing, creation, crash listing, builds listing, ACL, and
per-project settings/webhooks/device-url admin. Mechanical move from
server.py - routes and logic unchanged, endpoint names preserved exactly
(registered directly on the app object, not via Flask Blueprint - see
core.py for why)."""
from flask import current_app, redirect, request, session, url_for
from sqlalchemy import delete, func, insert, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from device_url import DEVICE_ID_PLACEHOLDER, device_url_template_is_valid

from ..auth import auth_filter, login_required
from ..models import (
    Crash, CrashTag, Device, ElfFile, ProjectAuth, ProjectSettings,
    ProjectSlackIntegration, ProjectWebhook, Tag, db,
)
from ..rendering import render_template


@login_required
def list_project_crashes(project_name):
    """List crashes for a given project name."""
    search = request.args.get('search', None)
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))
    tag_id = request.args.get('tag_id', None)
    tag_id = int(tag_id) if tag_id else None
    signature = request.args.get('signature', None) or None

    conditions = [auth_filter(ProjectAuth.github)]
    if project_name:
        conditions.append(Crash.project_name == project_name)
    if search and len(search) > 0:
        conditions.append(Crash.textsearch.op("@@")(func.plainto_tsquery(search)))
    if tag_id:
        conditions.append(Crash.crash_id.in_(select(CrashTag.crash_id).where(CrashTag.tag_id == tag_id)))
    if signature:
        conditions.append(Crash.signature == signature)

    crashes = db.session.execute(
        select(
            Crash.crash_id,
            Crash.date,
            Crash.project_name,
            Crash.device_id,
            Crash.project_ver,
            Crash.module_names,
            Crash.signature,
            func.array_agg(ElfFile.elf_file_id).filter(ElfFile.elf_file_id.isnot(None)).label("elf_file_id"),
            func.array_agg(ElfFile.project_alias).label("project_alias"),
            Device.ext_device_id,
            Device.alias,
            ProjectSettings.device_url_template,
            func.count().over().label("full_count"),
        )
        .select_from(Crash)
        .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
        .outerjoin(ElfFile, (Crash.project_name == ElfFile.project_name) & (Crash.project_ver == ElfFile.project_ver))
        .outerjoin(Device, Crash.device_id == Device.device_id)
        .outerjoin(ProjectSettings, Crash.project_name == ProjectSettings.project_name)
        .where(*conditions)
        .group_by(
            Crash.crash_id,
            Crash.date,
            Crash.project_name,
            Crash.device_id,
            Crash.project_ver,
            Crash.signature,
            Device.ext_device_id,
            Device.alias,
            ProjectSettings.device_url_template,
        )
        .order_by(Crash.date.desc(), Crash.crash_id)
        .limit(limit)
        .offset(offset)
    ).mappings().all()

    # Tags aren't folded into the aggregate query above (it already juggles
    # an array_agg + a count() window) - fetch them in one batched query and
    # attach in Python, the same idiom used for builds in mcp_app/tools.py.
    crash_ids = [c["crash_id"] for c in crashes]
    tags_by_crash = {}
    if crash_ids:
        tag_rows = db.session.execute(
            select(CrashTag.crash_id, Tag.tag_id, Tag.name, Tag.description)
            .join(Tag, CrashTag.tag_id == Tag.tag_id)
            .where(CrashTag.crash_id.in_(crash_ids))
            .order_by(Tag.name)
        ).mappings().all()
        for t in tag_rows:
            tags_by_crash.setdefault(t["crash_id"], []).append(
                {"tag_id": t["tag_id"], "name": t["name"], "description": t["description"]}
            )
    # Related-crash counts (non-AI, see app/crash_signature.py) - batched the
    # same way as tags above rather than folded into the aggregate query.
    # count(distinct crash_id) because the ProjectAuth join above can fan
    # out per crash when a project has more than one ACL row (or in
    # no-auth mode, where every ProjectAuth row for a project matches) -
    # a plain count() would overcount in exactly those cases.
    signatures = {c["signature"] for c in crashes if c["signature"]}
    related_counts = {}
    if signatures:
        related_rows = db.session.execute(
            select(Crash.signature, func.count(func.distinct(Crash.crash_id)).label("cnt"))
            .select_from(Crash)
            .join(ProjectAuth, Crash.project_name == ProjectAuth.project_name)
            .where(Crash.signature.in_(signatures), auth_filter(ProjectAuth.github))
            .group_by(Crash.signature)
        ).mappings().all()
        related_counts = {r["signature"]: r["cnt"] for r in related_rows}

    crashes = [
        dict(
            c,
            tags=tags_by_crash.get(c["crash_id"], []),
            # -1 to exclude the crash itself from its own related count.
            related_count=max(0, related_counts.get(c["signature"], 0) - 1) if c["signature"] else 0,
        )
        for c in crashes
    ]

    active_tag = None
    if tag_id:
        active_tag = db.session.execute(
            select(Tag.name).where(Tag.tag_id == tag_id)
        ).scalar_one_or_none()

    # Only worth a whole column if at least one crash on this page actually
    # references a module - otherwise it's just an empty-dash column on
    # every row.
    any_modules = any(c["module_names"] for c in crashes)

    # crash.module_names is populated at cron processing time, so no per-row
    # coredump parsing happens here.
    return render_template('project.html', crashes = crashes, project_name = project_name, search = search or "", limit = limit, offset = offset, tag_id = tag_id, active_tag = active_tag, signature = signature, any_modules = any_modules, full_count = crashes[0]["full_count"] if len(crashes) > 0 else 0)


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

    projects = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).mappings().all()
    if len(projects) > 0:
        return "Project already registred, ask admin for invite", 400
    db.session.execute(
        insert(ProjectAuth).values(date=func.now(), project_name=project_name, github=session["gh_user"])
    )
    db.session.commit()
    return redirect(url_for("list_project_crashes", project_name=project_name), code=302)


@login_required
def list_builds(project_name):
    """List available build files for a project."""
    offset = int(request.args.get('offset', 0))
    limit = int(request.args.get('limit', 50))

    crash_count = (
        select(func.count())
        .where(Crash.project_name == ElfFile.project_name, Crash.project_ver == ElfFile.project_ver)
        .scalar_subquery()
    )
    builds = db.session.execute(
        select(
            ElfFile.elf_file_id,
            ElfFile.date,
            ElfFile.project_name,
            ElfFile.project_ver,
            ElfFile.project_alias,
            ElfFile.file_size,
            func.coalesce(crash_count, 0).label("crash_count"),
            func.count().over().label("full_count"),
        )
        .select_from(ElfFile)
        .join(ProjectAuth, ElfFile.project_name == ProjectAuth.project_name)
        .where(ElfFile.project_name == project_name, auth_filter(ProjectAuth.github))
        .order_by(ElfFile.date.desc())
        .limit(limit)
        .offset(offset)
    ).mappings().all()
    return render_template('builds.html', elfs = builds, project_name = project_name, limit=limit, offset=offset,  full_count = builds[0]["full_count"] if len(builds) > 0 else 0)


@login_required
def list_acl(project_name):
    """Redirect to project access control settings."""
    return redirect(url_for('project_settings', project_name=project_name))


@login_required
def create_acl(project_name):
    """Add a GitHub user to a project's access list."""
    acls = db.session.execute(
        select(ProjectAuth.project_name)
        .where(auth_filter(ProjectAuth.github), ProjectAuth.project_name == project_name)
        .limit(1)
    ).mappings().all()

    if len(acls) < 1:
        return "No access to create for this project", 500
    github = request.form['github']
    if len(github) < 1:
        return "Missing github name", 400

    acls = db.session.execute(
        select(ProjectAuth.github)
        .where(ProjectAuth.project_name == project_name, ProjectAuth.github == github)
    ).mappings().all()

    if len(acls) > 0:
        return "User already exists", 400

    db.session.execute(
        insert(ProjectAuth).values(date=func.now(), project_name=project_name, github=github)
    )
    db.session.commit()
    return redirect(url_for("project_settings", project_name = project_name), code=302)


@login_required
def delete_acl(project_name, github):
    """Remove a GitHub user from a project's access list."""
    db.session.execute(
        delete(ProjectAuth).where(
            ProjectAuth.github == github,
            ProjectAuth.project_name == project_name,
            auth_filter(ProjectAuth.github),
        )
    )
    db.session.commit()
    return redirect(url_for("project_settings", project_name = project_name), code=302)


@login_required
def project_settings(project_name):
    """Display and manage settings for a specific project."""
    # Verify user has access to this project
    allowed = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).mappings().all()
    if not allowed:
        return "Forbidden: You do not have access to this project.", 403

    acls = db.session.execute(
        select(ProjectAuth.github, ProjectAuth.date, ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name)
        .order_by(ProjectAuth.date.desc())
    ).mappings().all()

    # Rows (tuple-like) rather than mappings: the template indexes webhook[0]
    # / webhook[1], matching the original raw cursor().fetchall() shape.
    webhooks_list = db.session.execute(
        select(ProjectWebhook.webhook_id, ProjectWebhook.webhook_url)
        .where(ProjectWebhook.project_name == project_name)
        .order_by(ProjectWebhook.webhook_id)
    ).all()

    # Get Slack integrations
    slack_integrations = db.session.execute(
        select(
            ProjectSlackIntegration.slack_integration_id, ProjectSlackIntegration.slack_team_id,
            ProjectSlackIntegration.slack_team_name, ProjectSlackIntegration.slack_channel_id,
            ProjectSlackIntegration.slack_channel_name, ProjectSlackIntegration.created_date,
        )
        .where(ProjectSlackIntegration.project_name == project_name)
        .order_by(ProjectSlackIntegration.created_date.desc())
    ).mappings().all()

    settings_row = db.session.execute(
        select(ProjectSettings.device_url_template)
        .where(ProjectSettings.project_name == project_name)
    ).mappings().all()
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
    # Permission check: Ensure user is authorized for this project
    auth_check = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).mappings().all()
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
            existing = db.session.execute(
                select(ProjectWebhook.webhook_id)
                .where(ProjectWebhook.project_name == project_name, ProjectWebhook.webhook_url == webhook_url)
            ).first()
            if existing:
                # Optionally, flash a message: "Webhook URL already exists for this project."
                pass # Or return some error/message
            else:
                db.session.execute(
                    insert(ProjectWebhook).values(project_name=project_name, webhook_url=webhook_url)
                )
                db.session.commit()

        elif action == 'delete':
            webhook_id = request.form.get('webhook_id')
            if not webhook_id:
                return "Webhook ID is required for deletion.", 400

            # The permission check at the beginning covers project-level access.
            # Deleting by webhook_id and project_name ensures we only delete from the correct project.
            db.session.execute(
                delete(ProjectWebhook)
                .where(ProjectWebhook.webhook_id == webhook_id, ProjectWebhook.project_name == project_name)
            )
            db.session.commit()

        return redirect(url_for('project_settings', project_name=project_name))

    # GET request logic
    return redirect(url_for('project_settings', project_name=project_name))


@login_required
def project_device_url_admin(project_name):
    """Save (or clear) the per-project device-id URL template."""
    # Permission check: same gate as the rest of the project settings.
    auth_check = db.session.execute(
        select(ProjectAuth.project_name)
        .where(ProjectAuth.project_name == project_name, auth_filter(ProjectAuth.github))
    ).mappings().all()
    if not auth_check:
        return "Forbidden: You do not have access to this project.", 403

    template = (request.form.get('device_url_template') or '').strip()

    # A non-blank template must contain the {device_id} placeholder; blank clears it.
    if not device_url_template_is_valid(template):
        return redirect(url_for('project_settings', project_name=project_name, device_url_error='1'))

    stmt = pg_insert(ProjectSettings).values(
        project_name=project_name, device_url_template=(template or None)
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=["project_name"],
        set_={"device_url_template": stmt.excluded.device_url_template},
    )
    db.session.execute(stmt)
    db.session.commit()

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
