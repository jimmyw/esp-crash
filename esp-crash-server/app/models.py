"""SQLAlchemy ORM models + the Flask-SQLAlchemy `db` handle.

One model per table, matching the schema managed by the Alembic migrations in
`alembic/versions/` column-for-column, index-for-index. The `update_textsearch`
trigger/function on `crash` is NOT modelled here (SQLAlchemy doesn't manage
triggers); it lives in the Alembic migration and stays in the database.
"""
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TSVECTOR

db = SQLAlchemy()


class Device(db.Model):
    __tablename__ = "device"

    device_id = db.Column(db.Integer, primary_key=True)
    ext_device_id = db.Column(db.Text, unique=True)
    alias = db.Column(db.Text)


class Crash(db.Model):
    __tablename__ = "crash"
    __table_args__ = (
        db.Index("textsearch_idx", "textsearch", postgresql_using="gin"),
        db.Index("idx_crash_project_name_ver", "project_name", "project_ver"),
        db.Index("idx_crash_signature", "signature"),
    )

    crash_id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.TIMESTAMP)
    project_name = db.Column(db.Text)
    project_ver = db.Column(db.Text)
    crash_dmp = db.Column(db.LargeBinary)
    device_id = db.Column(
        db.Integer, db.ForeignKey("device.device_id"), nullable=False
    )
    textsearch = db.Column(TSVECTOR)
    dump = db.Column(db.Text)
    module_names = db.Column(ARRAY(db.Text))
    module_map = db.Column(JSONB)
    # Non-AI duplicate-grouping fingerprint - see app/crash_signature.py.
    # NULL for crashes not yet backfilled or whose dump has no parseable
    # GDB backtrace. AI review (ai_title/ai_summary) and tags live on the
    # CrashRelation this signature points at, not on the crash itself - a
    # crash with signature IS NULL has no relation and so can't have
    # either.
    signature = db.Column(db.Text)


class ElfFile(db.Model):
    __tablename__ = "elf_file"
    __table_args__ = (
        db.Index("idx_elf_file_project", "project_name", "project_ver"),
        db.Index("idx_elf_file_project_name", "project_name"),
        db.Index(
            "idx_elf_file_project_date",
            "project_name",
            db.text("date DESC"),
        ),
    )

    elf_file_id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.TIMESTAMP)
    project_name = db.Column(db.Text)
    project_ver = db.Column(db.Text)
    elf_file = db.Column(db.LargeBinary)
    file_size = db.Column(db.Integer)
    project_alias = db.Column(db.Text)


class ProjectAuth(db.Model):
    __tablename__ = "project_auth"
    __table_args__ = (
        db.Index("idx_project_auth_lookup", "project_name", "github"),
    )

    project_auth_id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.TIMESTAMP)
    project_name = db.Column(db.Text)
    github = db.Column(db.Text)


class ProjectWebhook(db.Model):
    __tablename__ = "project_webhooks"

    webhook_id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.Text)
    webhook_url = db.Column(db.Text)


class ProjectSlackIntegration(db.Model):
    __tablename__ = "project_slack_integrations"
    __table_args__ = (
        db.Index("idx_project_slack_integrations_project", "project_name"),
        db.Index("idx_project_slack_integrations_team", "slack_team_id"),
    )

    slack_integration_id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.Text)
    slack_team_id = db.Column(db.Text)
    slack_team_name = db.Column(db.Text)
    slack_channel_id = db.Column(db.Text)
    slack_channel_name = db.Column(db.Text)
    slack_access_token = db.Column(db.Text)
    created_date = db.Column(db.TIMESTAMP, server_default=db.func.now())
    github_user = db.Column(db.Text)


class ProjectSettings(db.Model):
    __tablename__ = "project_settings"

    project_name = db.Column(db.Text, primary_key=True)
    device_url_template = db.Column(db.Text)


class Tag(db.Model):
    __tablename__ = "tag"
    __table_args__ = (
        db.UniqueConstraint("project_name", "name", name="uq_tag_project_name_name"),
        db.Index("idx_tag_project_name", "project_name"),
    )

    tag_id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.Text, nullable=False)
    name = db.Column(db.Text, nullable=False)
    description = db.Column(db.Text)


class CrashRelation(db.Model):
    """Owns the AI review (ai_title/ai_summary) and, via CrashRelationTag,
    the tags for every crash sharing a (project_name, signature) - see
    app/ai_tagging.py. Crash rows link here implicitly by matching their
    own project_name/signature; there is no FK column on crash_relation
    pointing back, since many crashes point at one relation."""
    __tablename__ = "crash_relation"

    project_name = db.Column(db.Text, primary_key=True)
    signature = db.Column(db.Text, primary_key=True)
    ai_title = db.Column(db.Text)
    ai_summary = db.Column(db.Text)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())


class CrashRelationTag(db.Model):
    __tablename__ = "crash_relation_tag"
    __table_args__ = (
        db.ForeignKeyConstraint(
            ["project_name", "signature"],
            ["crash_relation.project_name", "crash_relation.signature"],
            ondelete="CASCADE",
        ),
        db.Index("idx_crash_relation_tag_tag_id", "tag_id"),
    )

    project_name = db.Column(db.Text, primary_key=True)
    signature = db.Column(db.Text, primary_key=True)
    tag_id = db.Column(
        db.Integer, db.ForeignKey("tag.tag_id", ondelete="CASCADE"), primary_key=True
    )


class McpOAuthClient(db.Model):
    """Dynamically-registered MCP OAuth clients (RFC 7591). `data` is the
    full serialized mcp.shared.auth.OAuthClientInformationFull - stored as a
    blob rather than column-per-field so the store tracks the SDK's model
    without a migration every time it gains a field."""
    __tablename__ = "mcp_oauth_client"

    client_id = db.Column(db.Text, primary_key=True)
    data = db.Column(JSONB, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())


class McpAccessToken(db.Model):
    """Issued MCP bearer access tokens. expires_at is duplicated out of
    `data` (a serialized mcp.server.auth.provider.AccessToken) as a plain
    column purely so expiry can be checked/cleaned up in SQL."""
    __tablename__ = "mcp_access_token"
    __table_args__ = (
        db.Index("idx_mcp_access_token_expires_at", "expires_at"),
    )

    token = db.Column(db.Text, primary_key=True)
    client_id = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.BigInteger)
    data = db.Column(JSONB, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())


class McpRefreshToken(db.Model):
    """Issued MCP refresh tokens (serialized mcp.server.auth.provider.RefreshToken)."""
    __tablename__ = "mcp_refresh_token"

    token = db.Column(db.Text, primary_key=True)
    client_id = db.Column(db.Text, nullable=False)
    data = db.Column(JSONB, nullable=False)
    created_at = db.Column(db.TIMESTAMP, server_default=db.func.now())


class ModuleElf(db.Model):
    __tablename__ = "module_elf"
    __table_args__ = (
        db.Index("module_elf_app_sha1_idx", "app_sha1"),
    )

    module_elf_id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.TIMESTAMP, server_default=db.func.now())
    name = db.Column(db.Text, nullable=False)
    app_sha1 = db.Column(db.CHAR(40), nullable=False, unique=True)
    elf_file = db.Column(db.LargeBinary, nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
