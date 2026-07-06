"""Shared seeding/fixture-data helpers for the characterization test suite.

Plain functions, not pytest fixtures - call them with the `db_conn` fixture
from conftest.py to arrange DB state directly, bypassing the app's routes.
"""
import bz2

import psycopg2


def create_project(db_conn, project_name, github_user="none"):
    with db_conn.cursor() as cur:
        cur.execute(
            "INSERT INTO project_auth (date, project_name, github) VALUES (NOW(), %s, %s)",
            (project_name, github_user),
        )


def create_device(db_conn, ext_device_id, alias=None):
    with db_conn.cursor() as cur:
        cur.execute(
            "INSERT INTO device (ext_device_id, alias) VALUES (%s, %s) RETURNING device_id",
            (ext_device_id, alias),
        )
        return cur.fetchone()[0]


def create_crash(db_conn, project_name, project_ver, device_id, crash_dmp=b"raw-dump-bytes", dump=None):
    with db_conn.cursor() as cur:
        cur.execute(
            """INSERT INTO crash (date, project_name, project_ver, crash_dmp, device_id, dump)
               VALUES (NOW(), %s, %s, %s, %s, %s) RETURNING crash_id""",
            (project_name, project_ver, psycopg2.Binary(crash_dmp), device_id, dump),
        )
        return cur.fetchone()[0]


def create_elf_file(db_conn, project_name, project_ver, elf_bytes=b"raw-elf-bytes", project_alias=None):
    with db_conn.cursor() as cur:
        cur.execute(
            """INSERT INTO elf_file (date, project_name, project_ver, elf_file, file_size, project_alias)
               VALUES (NOW(), %s, %s, %s, %s, %s) RETURNING elf_file_id""",
            (project_name, project_ver, psycopg2.Binary(elf_bytes), len(elf_bytes), project_alias),
        )
        return cur.fetchone()[0]


def create_module_elf(db_conn, name, app_sha1, elf_bytes=b"raw-module-elf-bytes"):
    with db_conn.cursor() as cur:
        cur.execute(
            """INSERT INTO module_elf (date, name, app_sha1, elf_file, file_size)
               VALUES (NOW(), %s, %s, %s, %s) RETURNING module_elf_id""",
            (name, app_sha1, psycopg2.Binary(elf_bytes), len(elf_bytes)),
        )
        return cur.fetchone()[0]


def create_webhook(db_conn, project_name, webhook_url):
    with db_conn.cursor() as cur:
        cur.execute(
            "INSERT INTO project_webhooks (project_name, webhook_url) VALUES (%s, %s) RETURNING webhook_id",
            (project_name, webhook_url),
        )
        return cur.fetchone()[0]


def create_slack_integration(db_conn, project_name, **overrides):
    fields = {
        "slack_team_id": "T123",
        "slack_team_name": "Test Team",
        "slack_channel_id": "C123",
        "slack_channel_name": "general",
        "slack_access_token": "xoxb-fake-token",
        "github_user": "none",
    }
    fields.update(overrides)
    with db_conn.cursor() as cur:
        cur.execute(
            """INSERT INTO project_slack_integrations
               (project_name, slack_team_id, slack_team_name, slack_channel_id,
                slack_channel_name, slack_access_token, github_user)
               VALUES (%(project_name)s, %(slack_team_id)s, %(slack_team_name)s,
                       %(slack_channel_id)s, %(slack_channel_name)s,
                       %(slack_access_token)s, %(github_user)s)
               RETURNING slack_integration_id""",
            {"project_name": project_name, **fields},
        )
        return cur.fetchone()[0]


# --- synthetic binary fixtures -------------------------------------------------
# Tiny, made up, never real production firmware/coredumps.

def crash_dump_bytes(project_name="test-firmware", project_ver="1.55", device_id="aaa-bbb", compressed=False):
    marker = f"ESP_CRASH:{project_name};{project_ver};{device_id};\n".encode()
    payload = marker + b"synthetic crash body padding\n" * 4
    return bz2.compress(payload) if compressed else payload


def elf_file_bytes(project_name=None, project_ver=None, with_marker=True):
    if with_marker and project_name and project_ver:
        header = f"ESP_CRASH:{project_name};{project_ver};dev-marker;\n".encode()
    else:
        header = b""
    return header + b"\x7fELF" + b"\x00" * 12 + b"synthetic-elf-payload" * 4


VALID_SHA1 = "a" * 40
INVALID_SHA1 = "not-a-valid-sha1"
