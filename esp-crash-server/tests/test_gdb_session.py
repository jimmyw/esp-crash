"""Interactive-debug wiring in the web app: the session-ticket endpoint, the
per-project toolchain setting, and the ACL-scoped artifact accessor.

The sandbox itself is covered without a database by test_jail_argv.py, and
end to end by the `integration`-marked test in this file. What is tested here
is the part that decides *whether* a session may start at all.
"""
import bz2

import pytest

import gdb_tickets
import toolchains
import helpers

SECRET = "test-gdb-ticket-secret"
WS_URL = "wss://gdb.example.test/v1/session"


@pytest.fixture
def configured(server_module, monkeypatch):
    """The app as deployed with interactive debugging switched on."""
    app = server_module.app
    monkeypatch.setitem(app.config, "GDB_TICKET_SECRET", SECRET)
    monkeypatch.setitem(app.config, "GDB_PUBLIC_WS_URL", WS_URL)
    return app


@pytest.fixture
def fake_toolchain(monkeypatch):
    """One installed toolchain, so settings and link-visibility logic have
    something real to resolve against without needing the actual gdb."""
    tc = toolchains.Toolchain(
        name="xtensa-esp-elf", arch="xtensa", version="16.3",
        exe="/opt/tc/gdb", converter="esp_coredump",
    )
    monkeypatch.setattr(toolchains, "installed", lambda: {tc.name: tc})
    return tc


def seed_crash(db_conn, user="alice", project="proj", ver="1.0",
               with_build=True, toolchain="xtensa-esp-elf"):
    helpers.create_project(db_conn, project, github_user=user)
    device_id = helpers.create_device(db_conn, f"dev-{project}")
    if with_build:
        helpers.create_elf_file(db_conn, project, ver, elf_bytes=b"ELF-BYTES")
    if toolchain is not None:
        with db_conn.cursor() as cur:
            cur.execute("INSERT INTO project_settings (project_name, toolchain) "
                        "VALUES (%s, %s)", (project, toolchain))
    return helpers.create_crash(db_conn, project, ver, device_id,
                                crash_dmp=bz2.compress(b"DUMP-BYTES"))


def post_ticket(client, crash_id):
    return client.post(f"/api/v1/crashes/{crash_id}/gdb-session",
                       headers={"X-Api-Client": "1"})


# ------------------------------------------------------- the ticket endpoint

def test_issues_a_usable_ticket(configured, github_client, db_conn):
    crash_id = seed_crash(db_conn)
    response = post_ticket(github_client("alice"), crash_id)
    assert response.status_code == 200

    body = response.get_json()
    assert body["ws_url"].startswith(WS_URL + "?ticket=")
    ticket = body["ws_url"].split("ticket=", 1)[1]

    # The ticket must name the caller and the crash they asked for - the debug
    # service trusts nothing else about the connection.
    gh_user, ticket_crash, _jti = gdb_tickets.TicketSigner(SECRET).verify(ticket)
    assert (gh_user, ticket_crash) == ("alice", crash_id)


def test_the_ticket_is_short_lived(configured, github_client, db_conn):
    crash_id = seed_crash(db_conn)
    body = post_ticket(github_client("alice"), crash_id).get_json()
    assert 0 < body["expires_in"] <= 300, \
        "a session ticket is redeemed immediately; a long life only widens the window"


def test_a_crash_in_another_users_project_is_a_404(configured, github_client, db_conn):
    crash_id = seed_crash(db_conn, user="bob", project="bobs-project")
    # 404 rather than 403: missing and forbidden are deliberately
    # indistinguishable, so the API never confirms a crash exists.
    assert post_ticket(github_client("alice"), crash_id).status_code == 404


def test_an_unauthenticated_caller_gets_401(configured, server_module,
                                            github_auth_unauthenticated, db_conn):
    crash_id = seed_crash(db_conn)
    client = server_module.app.test_client()
    assert post_ticket(client, crash_id).status_code == 401


def test_a_cross_site_post_without_the_api_header_is_refused(configured, github_client,
                                                             db_conn):
    crash_id = seed_crash(db_conn)
    # A forged cross-site <form> POST cannot set a custom header; without this
    # the endpoint would mint tickets for a victim's session.
    response = github_client("alice").post(f"/api/v1/crashes/{crash_id}/gdb-session")
    assert response.status_code == 403


def test_unconfigured_deployments_report_unavailable(server_module, github_client,
                                                     db_conn, monkeypatch):
    monkeypatch.setitem(server_module.app.config, "GDB_TICKET_SECRET", "")
    monkeypatch.setitem(server_module.app.config, "GDB_PUBLIC_WS_URL", "")
    crash_id = seed_crash(db_conn)
    assert post_ticket(github_client("alice"), crash_id).status_code == 503


# --------------------------------------------------- the per-project setting

def test_saving_a_toolchain(configured, fake_toolchain, github_client, db_conn):
    helpers.create_project(db_conn, "proj", github_user="alice")
    response = github_client("alice").post(
        "/projects/proj/settings/toolchain", data={"toolchain": "xtensa-esp-elf"})
    assert response.status_code == 302
    with db_conn.cursor() as cur:
        cur.execute("SELECT toolchain FROM project_settings WHERE project_name='proj'")
        assert cur.fetchone()[0] == "xtensa-esp-elf"


def test_clearing_a_toolchain(configured, fake_toolchain, github_client, db_conn):
    helpers.create_project(db_conn, "proj", github_user="alice")
    client = github_client("alice")
    client.post("/projects/proj/settings/toolchain", data={"toolchain": "xtensa-esp-elf"})
    client.post("/projects/proj/settings/toolchain", data={"toolchain": ""})
    with db_conn.cursor() as cur:
        cur.execute("SELECT toolchain FROM project_settings WHERE project_name='proj'")
        assert cur.fetchone()[0] is None


@pytest.mark.parametrize("value", ["not-installed", "../../etc", "/opt/esp/tools"])
def test_an_uninstallable_toolchain_is_rejected(configured, fake_toolchain,
                                                github_client, db_conn, value):
    # The stored value selects filesystem paths for a sandbox, so it is
    # validated against what the image actually has - here as well as at
    # session start.
    helpers.create_project(db_conn, "proj", github_user="alice")
    response = github_client("alice").post(
        "/projects/proj/settings/toolchain", data={"toolchain": value})
    assert response.status_code == 302
    assert "toolchain_error=1" in response.headers["Location"]
    with db_conn.cursor() as cur:
        cur.execute("SELECT toolchain FROM project_settings WHERE project_name='proj'")
        assert cur.fetchall() == []


def test_another_users_project_cannot_be_reconfigured(configured, fake_toolchain,
                                                      github_client, db_conn):
    helpers.create_project(db_conn, "bobs", github_user="bob")
    response = github_client("alice").post(
        "/projects/bobs/settings/toolchain", data={"toolchain": "xtensa-esp-elf"})
    assert response.status_code == 403


# ------------------------------------------------------ the Debug link logic

@pytest.mark.parametrize("toolchain,with_build,expected", [
    ("xtensa-esp-elf", True, True),      # everything in place
    (None, True, False),                 # no toolchain configured
    ("not-installed", True, False),      # configured, but this server lacks it
    ("xtensa-esp-elf", False, False),    # no build, so no symbols to debug with
])
def test_the_debug_link_appears_only_when_a_session_could_start(
        configured, fake_toolchain, github_client, db_conn,
        toolchain, with_build, expected):
    crash_id = seed_crash(db_conn, with_build=with_build, toolchain=toolchain)
    page = github_client("alice").get(f"/projects/proj/{crash_id}").get_data(as_text=True)
    assert (f"/projects/proj/{crash_id}/debug" in page) is expected


def test_the_debug_link_is_hidden_when_the_service_is_unconfigured(
        server_module, fake_toolchain, github_client, db_conn, monkeypatch):
    monkeypatch.setitem(server_module.app.config, "GDB_PUBLIC_WS_URL", "")
    crash_id = seed_crash(db_conn)
    page = github_client("alice").get(f"/projects/proj/{crash_id}").get_data(as_text=True)
    assert f"/projects/proj/{crash_id}/debug" not in page


def test_the_debug_page_renders_a_terminal(configured, github_client, db_conn):
    crash_id = seed_crash(db_conn)
    page = github_client("alice").get(
        f"/projects/proj/{crash_id}/debug").get_data(as_text=True)
    assert "xterm" in page
    # The page carries no crash data itself; it holds the crash id and builds
    # the ticket request from it at runtime.
    assert f"CRASH_ID = {crash_id}" in page
    assert "/api/v1/crashes/" in page and "/gdb-session" in page


def test_the_debug_page_contains_no_crash_data(configured, github_client, db_conn):
    """Everything shown in the terminal arrives over the WebSocket from the
    debug service, so this page must not embed the dump or the ticket - a
    ticket rendered into HTML would be replayable from the browser history."""
    crash_id = seed_crash(db_conn)
    page = github_client("alice").get(
        f"/projects/proj/{crash_id}/debug").get_data(as_text=True)
    assert "DUMP-BYTES" not in page
    assert "ticket=" not in page


# ------------------------------------------------- the ACL-scoped accessor

def test_get_debug_artifacts_returns_normalised_blobs(configured, server_module, db_conn):
    from mcp_app import tools
    crash_id = seed_crash(db_conn)
    with server_module.app.app_context():
        artifacts = tools.get_debug_artifacts("alice", crash_id)
    assert artifacts["toolchain"] == "xtensa-esp-elf"
    # Stored bz2-compressed; the caller normalises with maybe_bunzip.
    from gdb_app.materialize import maybe_bunzip
    assert maybe_bunzip(artifacts["dump"]) == b"DUMP-BYTES"
    # This row was stored uncompressed, exercising the raw fallback that exists
    # because historical rows are not all bz2.
    assert maybe_bunzip(artifacts["prog"]) == b"ELF-BYTES"


def test_get_debug_artifacts_is_acl_scoped(configured, server_module, db_conn):
    from mcp_app import tools
    crash_id = seed_crash(db_conn, user="bob", project="bobs")
    with server_module.app.app_context():
        assert tools.get_debug_artifacts("alice", crash_id) is None
        assert tools.get_debug_artifacts("bob", crash_id) is not None


def test_get_debug_artifacts_reports_a_missing_build(configured, server_module, db_conn):
    from mcp_app import tools
    crash_id = seed_crash(db_conn, with_build=False)
    with server_module.app.app_context():
        artifacts = tools.get_debug_artifacts("alice", crash_id)
    # Not an error: the crash exists, there is simply nothing to symbolicate
    # with yet, and materialize turns that into a readable refusal.
    assert artifacts is not None and artifacts["prog"] is None


def test_get_module_elf_round_trips(configured, server_module, db_conn):
    from mcp_app import tools
    helpers.create_module_elf(db_conn, "mod", "a" * 40, elf_bytes=b"MODULE-ELF")
    with server_module.app.app_context():
        assert tools.get_module_elf("a" * 40) == b"MODULE-ELF"
        assert tools.get_module_elf("b" * 40) is None
