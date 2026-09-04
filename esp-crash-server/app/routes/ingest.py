"""Device-facing ingestion endpoints: crash dump upload, firmware ELF
upload, module debug ELF upload. Mechanical move from server.py - routes and
logic unchanged, endpoint names preserved exactly (registered directly on
the app object, not via Flask Blueprint - see core.py for why). Deliberately
un-authenticated, same as the original (these are called by devices/CI, not
browser users)."""
import re
import bz2

from flask import current_app, request
from sqlalchemy import func, insert, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from ..models import Crash, Device, ElfFile, ModuleElf, db
from ..rendering import external_url_for


def dump():
    """Upload a crash dump from a device."""
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

    # Rate limiting: Check if device has uploaded more than 5 crashes in the last hour
    crash_count = db.session.execute(
        select(func.count())
        .select_from(Crash)
        .join(Device, Crash.device_id == Device.device_id)
        .where(
            Device.ext_device_id == arguments["DEVICE_ID"],
            Crash.date >= text("now() - interval '1 hour'"),
        )
    ).scalar()

    if crash_count >= 5:
        return "Rate limit exceeded: Maximum 5 crashes per device per hour", 429

    upsert = pg_insert(Device).values(ext_device_id=arguments["DEVICE_ID"])
    upsert = upsert.on_conflict_do_update(
        index_elements=["ext_device_id"],
        set_={"ext_device_id": upsert.excluded.ext_device_id},
    ).returning(Device.device_id)
    device_id = db.session.execute(upsert).scalar()

    crash_id = db.session.execute(insert(Crash).values(
        date=func.now(),
        project_name=arguments["PROJECT_NAME"],
        project_ver=arguments["PROJECT_VER"],
        crash_dmp=compressed_content,
        device_id=device_id,
    ).returning(Crash.crash_id)).scalar()

    # Commit the changes and close the connection
    db.session.commit()

    # Hand back a link to what was just stored, so whatever uploaded it can
    # log or forward somewhere to look. `/crash/<id>` rather than a
    # project-scoped URL because of what the uploader knows: the crash id and
    # nothing else. That route infers the project (see
    # app/routes/crashes.py:show_crash) and is scoped like every other page, so
    # an id alone never reveals which project it belongs to.
    #
    # The body is the URL and nothing else - the 200 already says it worked, so
    # a status word in front of it would only be something to strip.
    return f"{external_url_for('show_crash', crash_id=crash_id)}\n", 200


def upload_elf():
    """Upload an ELF file containing build information."""
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
    db.session.execute(insert(ElfFile).values(
        date=func.now(),
        project_name=project_name,
        project_ver=project_ver,
        elf_file=compressed_content,
        file_size=len(compressed_content),
    ))

    # Commit the changes and close the connection
    db.session.commit()

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

    stmt = pg_insert(ModuleElf).values(
        date=func.now(),
        name=name,
        app_sha1=app_sha1,
        elf_file=compressed,
        file_size=uncompressed_size,
    ).on_conflict_do_nothing(index_elements=["app_sha1"])
    db.session.execute(stmt)
    db.session.commit()
    current_app.logger.info(f"Stored module_elf name={name} app_sha1={app_sha1} size={uncompressed_size}")
    return "OK\n", 200


def register(app):
    app.add_url_rule('/dump', endpoint="dump", view_func=dump, methods=['POST'])
    app.add_url_rule('/upload_elf', endpoint="upload_elf", view_func=upload_elf, methods=['POST'])
    app.add_url_rule('/upload_module_elf', endpoint="upload_module_elf", view_func=upload_module_elf, methods=['POST'])
