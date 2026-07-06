"""Device-facing ingestion endpoints: crash dump upload, firmware ELF
upload, module debug ELF upload. Mechanical move from server.py - routes and
logic unchanged, endpoint names preserved exactly (registered directly on
the app object, not via Flask Blueprint - see core.py for why). Deliberately
un-authenticated, same as the original (these are called by devices/CI, not
browser users)."""
import re
import bz2

import psycopg2
from flask import current_app, request

from ..db import ldb


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

    current_app.logger.info("Adding elf file")
    current_app.logger.info(f"Project name: '{project_name}'")
    current_app.logger.info(f"Project version: '{project_ver}'")


    # Execute the SQL query to insert the compressed file content into the database
    cursor = conn.cursor()
    cursor.execute('INSERT INTO elf_file (date, project_name, project_ver, elf_file, file_size) VALUES (NOW(), %s, %s, %s, %s)',
    (project_name, project_ver, psycopg2.Binary(compressed_content), len(compressed_content)))

    # Commit the changes and close the connection
    conn.commit()

    # Return a success message
    return "OK", 200


def upload_module_elf():
    """Upload a module debug ELF, identified by SHA1 of the wire .app bytes."""
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    name = request.args.get('name') or request.form.get('name')
    app_sha1 = request.args.get('app_sha1') or request.form.get('app_sha1')

    if not name:
        return "Missing name", 400
    if not app_sha1 or len(app_sha1) != 40 or not all(c in '0123456789abcdefABCDEF' for c in app_sha1):
        return "Missing or malformed app_sha1 (expect 40 hex chars)", 400
    app_sha1 = app_sha1.lower()

    raw = file.read()
    # Store compressed; record the uncompressed size. Accept either a raw ELF
    # or an already-bz2-compressed upload (decompress only once to detect).
    try:
        uncompressed_size = len(bz2.decompress(raw))
        compressed = raw
    except IOError:
        compressed = bz2.compress(raw)
        uncompressed_size = len(raw)

    db = ldb()
    cur = db.cursor()
    cur.execute(
        """
        INSERT INTO module_elf (date, name, app_sha1, elf_file, file_size)
        VALUES (NOW(), %s, %s, %s, %s)
        ON CONFLICT (app_sha1) DO NOTHING
        """,
        (name, app_sha1, psycopg2.Binary(compressed), uncompressed_size),
    )
    db.commit()
    current_app.logger.info(f"Stored module_elf name={name} app_sha1={app_sha1} size={uncompressed_size}")
    return "OK\n", 200


def register(app):
    app.add_url_rule('/dump', endpoint="dump", view_func=dump, methods=['POST'])
    app.add_url_rule('/upload_elf', endpoint="upload_elf", view_func=upload_elf, methods=['POST'])
    app.add_url_rule('/upload_module_elf', endpoint="upload_module_elf", view_func=upload_module_elf, methods=['POST'])
