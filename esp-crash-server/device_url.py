"""Pure helpers for the per-project device-id URL template.

Kept separate from server.py so the logic can be unit-tested without importing
the Flask app and its OAuth/Slack setup.
"""
import urllib.parse

# The single supported placeholder token, substituted with the (URL-encoded)
# device identifier the device reported (its burn-in QR code, or MAC fallback).
DEVICE_ID_PLACEHOLDER = "{device_id}"


def device_url_template_is_valid(template):
    """A blank template is valid (it clears the setting). A non-blank template
    must contain the {device_id} placeholder, otherwise it can never produce a
    working link."""
    if not template or not template.strip():
        return True
    return DEVICE_ID_PLACEHOLDER in template


def resolve_device_url(template, device_id):
    """Substitute the URL-encoded device id into the template.

    Returns None when there is no usable template (blank, or missing the
    placeholder) so callers can simply skip rendering the link.
    """
    if not template or DEVICE_ID_PLACEHOLDER not in template:
        return None
    encoded = urllib.parse.quote(device_id or "", safe="")
    return template.replace(DEVICE_ID_PLACEHOLDER, encoded)
