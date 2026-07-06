"""Device detail and alias update. Mechanical move from server.py - routes
and logic unchanged, endpoint names preserved exactly (registered directly
on the app object, not via Flask Blueprint - see core.py for why)."""
from flask import request

from ..auth import login_required
from ..db import ldb
from ..rendering import render_template


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
    ldb().commit()
    print(res)
    return show_device(device_id)


def register(app):
    app.add_url_rule('/device/<device_id>', endpoint="show_device", view_func=show_device)
    app.add_url_rule('/device/<device_id>', endpoint="update_device_alias", view_func=update_device_alias, methods=['POST'])
