"""Device detail and alias update. Mechanical move from server.py - routes
and logic unchanged, endpoint names preserved exactly (registered directly
on the app object, not via Flask Blueprint - see core.py for why)."""
from flask import request
from sqlalchemy import select, update

from ..auth import login_required
from ..models import Device, db
from ..rendering import render_template


@login_required
def show_device(device_id):
    """Display details for a specific device."""
    #app.logger.info(device_id)
    devices = db.session.execute(
        select(Device.device_id, Device.ext_device_id, Device.alias)
        .where(Device.device_id == device_id)
    ).mappings().all()
    if len(devices) == 1:
        return render_template('device.html', device = devices[0])
    return "Device not found", 400


@login_required
def update_device_alias(device_id):
    """Update the user-defined alias for a device."""
    # Extract the new alias from the POST data
    new_alias = request.form.get('alias')

    db.session.execute(
        update(Device).where(Device.device_id == device_id).values(alias=new_alias)
    )
    db.session.commit()
    return show_device(device_id)


def register(app):
    app.add_url_rule('/device/<device_id>', endpoint="show_device", view_func=show_device)
    app.add_url_rule('/device/<device_id>', endpoint="update_device_alias", view_func=update_device_alias, methods=['POST'])
