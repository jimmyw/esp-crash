"""GET/PATCH /api/v1/devices/<id>."""
from apiflask import abort
from flask import session

from mcp_app import tools

from ..auth import api_login_required
from . import api_v1
from .schema import not_found_if_none
from .schemas import AliasInSchema, DeviceSchema


@api_v1.get("/devices/<int:device_id>")
@api_v1.output(DeviceSchema)
@api_login_required
def get_device(device_id):
    """A device the caller can access - i.e. it has appeared in a crash
    under one of the caller's projects."""
    return not_found_if_none(tools.get_device(session["gh_user"], device_id), "Device not found")


@api_v1.patch("/devices/<int:device_id>")
@api_v1.input(AliasInSchema)
@api_login_required
def set_device_alias(device_id, json_data):
    """Set (or clear) the user-defined alias for a device."""
    result = tools.set_device_alias(session["gh_user"], device_id, json_data["alias"])
    if not result["updated"]:
        abort(404, message="Device not found or not accessible")
    return result
