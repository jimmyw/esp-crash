"""OpenAPI fragments for the device-facing ingestion endpoints.

These three are the endpoints devices and CI actually call, so they are the
ones most worth having in the published docs - but they sit outside
`/api/v1`, are registered directly on the app (see app/routes/ingest.py), and
predate this API by years. Two consequences shape what is here.

They are documented rather than decorated. APIFlask's `@app.input` would give
these views request validation, which changes what a device gets back: a
missing file part currently answers `400 No file part` as plain text, and
under a schema it would become a 422 JSON validation error. Firmware in the
field depends on the current behaviour, so the description lives beside the
route instead of on it, and nothing about the request path changes.

What APIFlask infers on its own is worse than nothing - it reports
`parameters: []` for endpoints that read query arguments, no request body for
endpoints whose entire input is an uploaded file, and `application/json`
responses for endpoints that only ever return plain text. Hence full path
items rather than a decorator that fills in some of it.

The drift risk this creates is covered by tests/test_api_docs.py, which
checks every documented path against the app's URL map and every documented
status code against what the view actually returns.
"""

TAG = {
    "name": "Ingestion",
    "description": (
        "Device- and CI-facing upload endpoints. Unauthenticated by design - "
        "they are called by firmware and build pipelines, not by browser "
        "users - and they answer in plain text, not JSON."
    ),
}

_FILE_BODY = {
    "required": True,
    "content": {
        "multipart/form-data": {
            "schema": {
                "type": "object",
                "required": ["file"],
                "properties": {
                    "file": {
                        "type": "string",
                        "format": "binary",
                        "description": "The file. bzip2-compressed or raw; "
                                       "the server detects which and stores "
                                       "it compressed either way.",
                    },
                },
            },
        },
    },
}


def _text(description, example=None):
    schema = {"type": "string"}
    if example is not None:
        schema["example"] = example
    return {"description": description, "content": {"text/plain": {"schema": schema}}}


INGEST_PATHS = {
    "/dump": {
        "post": {
            "tags": ["Ingestion"],
            "summary": "Upload a crash dump from a device",
            "description": (
                "Stores a raw core dump. The project, version and device are read "
                "from the `ESP_CRASH:<project>;<version>;<device>;` marker inside "
                "the dump itself, so no parameters are needed - a dump without "
                "that marker is rejected.\n\n"
                "Rate limited to 5 crashes per device per hour.\n\n"
                "The crash is stored undecoded; a background worker symbolicates "
                "it once a matching build has been uploaded via `/upload_elf`."
            ),
            "security": [],
            "requestBody": _FILE_BODY,
            "responses": {
                "200": _text(
                    "Stored. The body is a link to the crash and nothing else.",
                    "https://esp-crash.wennlund.nu/crash/116390",
                ),
                "400": _text(
                    "No file part, no selected file, or the dump carries no "
                    "usable ESP_CRASH identifier.",
                    "Missing ESP_CRASH identifier",
                ),
                "429": _text(
                    "Rate limit exceeded for this device.",
                    "Rate limit exceeded: Maximum 5 crashes per device per hour",
                ),
            },
        },
    },
    "/upload_elf": {
        "post": {
            "tags": ["Ingestion"],
            "summary": "Upload a build ELF, so crashes can be symbolicated",
            "description": (
                "Upload the unstripped ELF with debug symbols. Crashes are matched "
                "to a build by (project_name, project_ver).\n\n"
                "Both parameters are optional if the ELF contains an "
                "`ESP_CRASH:<project>;<version>;...` marker, which is read from the "
                "file first; an explicitly supplied value overrides it. They may be "
                "given as query arguments (shown here) or as form fields alongside "
                "the file."
            ),
            "security": [],
            "parameters": [
                {
                    "name": "project_name", "in": "query", "required": False,
                    "schema": {"type": "string"},
                    "description": "Overrides the project read from the ELF.",
                },
                {
                    "name": "project_ver", "in": "query", "required": False,
                    "schema": {"type": "string"},
                    "description": "Overrides the version read from the ELF.",
                },
            ],
            "requestBody": _FILE_BODY,
            "responses": {
                "200": _text("Stored.", "OK"),
                "500": _text(
                    "No file part, no selected file, or a project name/version "
                    "that could be neither read from the ELF nor supplied. "
                    "Historically a 500 rather than a 400; unchanged so that "
                    "existing build pipelines keep behaving as they do.",
                    "Missing project_name",
                ),
            },
        },
    },
    "/upload_module_elf": {
        "post": {
            "tags": ["Ingestion"],
            "summary": "Upload a runtime-loaded module's ELF",
            "description": (
                "Symbols for a module the firmware loads at runtime, so its frames "
                "resolve in a backtrace. Keyed by the module name and the SHA-1 of "
                "the application it belongs to.\n\n"
                "Both parameters may be given as query arguments (shown here) or as "
                "form fields alongside the file."
            ),
            "security": [],
            "parameters": [
                {
                    "name": "name", "in": "query", "required": True,
                    "schema": {"type": "string"},
                    "description": "Module name, as the firmware registers it.",
                },
                {
                    "name": "app_sha1", "in": "query", "required": True,
                    "schema": {"type": "string", "pattern": "^[0-9a-fA-F]{40}$"},
                    "description": "SHA-1 of the application this module belongs to.",
                },
            ],
            "requestBody": _FILE_BODY,
            "responses": {
                "200": _text("Stored.", "OK"),
                "400": _text(
                    "No file part, no selected file, a missing name, or an "
                    "app_sha1 that is not 40 hex characters.",
                    "Missing or malformed app_sha1 (expect 40 hex chars)",
                ),
            },
        },
    },
}
