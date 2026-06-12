"""Pure helpers for the per-project device-id URL template.

Kept separate from server.py so the logic can be unit-tested without importing
the Flask app and its OAuth/Slack setup.
"""
import urllib.parse

# The single supported placeholder token, substituted with the (URL-encoded)
# device identifier the device reported (its burn-in QR code, or MAC fallback).
DEVICE_ID_PLACEHOLDER = "{device_id}"

_ALLOWED_SCHEMES = ("http://", "https://")


def _has_safe_scheme(url):
    """Return True iff *url* starts with http:// or https:// (case-insensitive)."""
    lower = url.strip().lower()
    return any(lower.startswith(scheme) for scheme in _ALLOWED_SCHEMES)


def device_url_template_is_valid(template):
    """A blank template is valid (it clears the setting). A non-blank template
    must contain the {device_id} placeholder AND start with http:// or https://
    (case-insensitive). Any other scheme is rejected to prevent stored-XSS via
    javascript: or similar URIs."""
    if not template or not template.strip():
        return True
    return DEVICE_ID_PLACEHOLDER in template and _has_safe_scheme(template)


def resolve_device_url(template, device_id):
    """Substitute the URL-encoded device id into the template.

    Returns None when there is no usable template (blank, missing the
    placeholder, or a non-http(s) scheme) so callers can simply skip rendering
    the link. The scheme check neutralises any already-stored bad template at
    render time, acting as a defence-in-depth guard against stored XSS.
    """
    if not template or DEVICE_ID_PLACEHOLDER not in template:
        return None
    if not _has_safe_scheme(template):
        return None
    encoded = urllib.parse.quote(device_id or "", safe="")
    return template.replace(DEVICE_ID_PLACEHOLDER, encoded)
