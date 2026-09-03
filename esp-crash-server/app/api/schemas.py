"""Marshmallow schemas for the /api/v1 surface: @app.input(...) validates
request bodies/query strings, @app.output(...) documents+shapes JSON
responses, and both together are what APIFlask turns into the OpenAPI spec
served at /api/v1/openapi.json (Swagger UI at /api/v1/docs).

Nested, per-endpoint-varying substructures (a crash's tags/builds, a
relation's versions, etc.) use fields.List(fields.Dict()) rather than a
fully-typed nested schema for each - documents as "array of object" in the
spec without one-off schema classes for every relation shape. Top-level
fields (the ones the React app will actually bind to) are fully typed.

Mutation endpoints (POST/PUT/PATCH/DELETE) intentionally have no
@app.output schema - mcp_app/tools.py's return dicts vary shape by outcome
(e.g. {"added": False, "reason": "already exists"} vs {"added": True,
"webhook_id": ..., "webhook_url": ...}), and forcing every branch through
one strict schema would either drop fields or need a schema per branch for
little benefit over the plain JSON these already are. They're still
documented via @app.doc(description=...) at each route.
"""
from marshmallow import Schema, fields


def paginated_schema(item_schema_cls, name):
    """Build a `{"items": [...], "limit", "offset", "full_count"}` envelope
    schema wrapping the given item schema - the shape every list endpoint
    returns (see app/api/schema.py:paginated())."""
    return type(name, (Schema,), {
        "items": fields.List(fields.Nested(item_schema_cls)),
        "limit": fields.Int(),
        "offset": fields.Int(),
        "full_count": fields.Int(),
    })


# ---- output: item shapes ---------------------------------------------------

class ProjectSchema(Schema):
    project_name = fields.Str()
    crash_count = fields.Int()


class TagSchema(Schema):
    tag_id = fields.Int()
    name = fields.Str()
    description = fields.Str(allow_none=True)


class CrashListItemSchema(Schema):
    crash_id = fields.Int()
    date = fields.Str()
    project_name = fields.Str()
    project_ver = fields.Str(allow_none=True)
    device_id = fields.Int()
    ext_device_id = fields.Str(allow_none=True)
    alias = fields.Str(allow_none=True)
    module_names = fields.List(fields.Str(), allow_none=True)
    ai_title = fields.Str(allow_none=True)
    ai_summary = fields.Str(allow_none=True)
    signature = fields.Str(allow_none=True)
    tags = fields.List(fields.Dict())


class CrashDetailSchema(Schema):
    crash_id = fields.Int()
    date = fields.Str()
    project_name = fields.Str()
    project_ver = fields.Str(allow_none=True)
    device_id = fields.Int()
    ext_device_id = fields.Str(allow_none=True)
    alias = fields.Str(allow_none=True)
    dump = fields.Str(allow_none=True)
    module_map = fields.Raw(allow_none=True)
    module_names = fields.List(fields.Str(), allow_none=True)
    ai_title = fields.Str(allow_none=True)
    ai_summary = fields.Str(allow_none=True)
    signature = fields.Str(allow_none=True)
    # Debugger toolchain configured for the crash's project; None means no
    # interactive debug session is available for it.
    toolchain = fields.Str(allow_none=True)
    builds = fields.List(fields.Dict())
    tags = fields.List(fields.Dict())


class BuildSchema(Schema):
    elf_file_id = fields.Int()
    date = fields.Str()
    project_name = fields.Str()
    project_ver = fields.Str(allow_none=True)
    project_alias = fields.Str(allow_none=True)
    file_size = fields.Int()
    crash_count = fields.Int()


class DeviceSchema(Schema):
    device_id = fields.Int()
    ext_device_id = fields.Str(allow_none=True)
    alias = fields.Str(allow_none=True)


class RelationSchema(Schema):
    signature = fields.Str()
    ai_title = fields.Str(allow_none=True)
    crash_count = fields.Int()
    last_seen = fields.Str()
    tags = fields.List(fields.Dict())
    versions = fields.List(fields.Dict())


class AclSchema(Schema):
    github = fields.Str()
    date = fields.Str()


class WebhookSchema(Schema):
    webhook_id = fields.Int()
    webhook_url = fields.Str()


class SlackIntegrationSchema(Schema):
    slack_integration_id = fields.Int()
    slack_team_id = fields.Str(allow_none=True)
    slack_team_name = fields.Str(allow_none=True)
    slack_channel_id = fields.Str(allow_none=True)
    slack_channel_name = fields.Str(allow_none=True)
    created_date = fields.Str(allow_none=True)


class ProjectSettingsSchema(Schema):
    project_name = fields.Str()
    acl = fields.List(fields.Dict())
    webhooks = fields.List(fields.Dict())
    slack_integrations = fields.List(fields.Dict())
    device_url_template = fields.Str(allow_none=True)


ProjectListSchema = paginated_schema(ProjectSchema, "ProjectListSchema")
CrashListSchema = paginated_schema(CrashListItemSchema, "CrashListSchema")
BuildListSchema = paginated_schema(BuildSchema, "BuildListSchema")
RelationListSchema = paginated_schema(RelationSchema, "RelationListSchema")


# ---- input: query strings --------------------------------------------------

class PaginationQuerySchema(Schema):
    limit = fields.Int(load_default=50)
    offset = fields.Int(load_default=0)


class CrashListQuerySchema(PaginationQuerySchema):
    project_name = fields.Str(load_default=None, allow_none=True)
    search = fields.Str(load_default=None, allow_none=True)
    tag_id = fields.Int(load_default=None, allow_none=True)
    signature = fields.Str(load_default=None, allow_none=True)


# ---- input: JSON bodies -----------------------------------------------------

class ProjectCreateInSchema(Schema):
    project_name = fields.Str(required=True)


class TagAddInSchema(Schema):
    tag_name = fields.Str(required=True)
    tag_description = fields.Str(load_default=None, allow_none=True)


class AliasInSchema(Schema):
    alias = fields.Str(required=True, allow_none=True)


class AclAddInSchema(Schema):
    github = fields.Str(required=True)


class WebhookAddInSchema(Schema):
    webhook_url = fields.Str(required=True)


class DeviceUrlTemplateInSchema(Schema):
    device_url_template = fields.Str(required=True, allow_none=True)


class SlackChannelInSchema(Schema):
    channel_id = fields.Str(required=True)
    channel_name = fields.Str(required=True)


class GdbSessionSchema(Schema):
    """Everything the browser needs to open an interactive debug session: where
    to connect, and the short-lived ticket authorising it."""
    ws_url = fields.String()
    expires_in = fields.Integer()
    toolchain = fields.String(allow_none=True)
