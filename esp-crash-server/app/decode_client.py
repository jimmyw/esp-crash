"""Client for the debug service's batch decode endpoint.

Crash decoding used to happen in this process: shell out to esp-coredump and
gdb, parse the result. It now happens inside a bubblewrap sandbox in the debug
service, so this module is what replaces that - a single function cron calls,
and the single place to patch when testing callers.

Kept beside `app/decode.py` rather than replacing it, so the cut-over is one
environment variable on the cron container and is reversible without a deploy.
`app/decode.py` is the in-process path and goes away once this one has run in
production for a while.

The error split matters more than it looks. A *permanent* failure is stored as
the crash's dump so the crash stops being reprocessed on every tick - which is
what the old path did when it wrote "# esp-coredump unavailable: ...". A
*transient* one must leave the row untouched, because storing a message would
mark thousands of crashes decoded when the real problem was a misconfiguration.
"""
import os

import requests
from flask import current_app

DEFAULT_TIMEOUT_SECONDS = 900


class DecodeUnavailable(Exception):
    """Transient: leave `dump` NULL and let the next tick retry.

    Covers a service that is down or busy, a network failure, and every
    condition an operator or a later upload can fix - no build yet, no
    toolchain configured.
    """


class DecodePermanent(Exception):
    """Permanent: store the message as the dump so the crash stops requeueing.

    The artifact will not become decodable by being tried again.
    """


def configured():
    """Whether the service path is enabled. When it is not, callers keep using
    the in-process decode."""
    return bool(os.environ.get("DECODE_SERVICE_URL"))


def decode_crash(crash_id, elf_file_id=None):
    """Decode one crash through the debug service.

    Returns the service's result: `report`, `modules` (with section addresses),
    `module_names`, `toolchain`, `toolchain_source`, `elf_file_id`, `elf_count`.
    Raises DecodeUnavailable or DecodePermanent.
    """
    url = os.environ.get("DECODE_SERVICE_URL")
    token = os.environ.get("DECODE_SERVICE_TOKEN")
    if not url or not token:
        raise DecodeUnavailable(
            "DECODE_SERVICE_URL and DECODE_SERVICE_TOKEN must both be set")

    payload = {"crash_id": int(crash_id)}
    if elf_file_id is not None:
        payload["elf_file_id"] = int(elf_file_id)

    try:
        response = requests.post(
            url.rstrip("/") + "/v1/decode",
            json=payload,
            headers={"Authorization": f"Bearer {token}"},
            # Generously above the service's own per-phase timeouts: if this
            # gives up first the handler keeps running and holds a batch slot
            # until it finishes, which wastes capacity for nothing.
            timeout=_timeout(),
        )
    except requests.exceptions.RequestException as e:
        raise DecodeUnavailable(f"debug service unreachable: {e}") from None

    if response.status_code == 200:
        return response.json()

    try:
        error = response.json()["error"]
        message, retryable = error["message"], bool(error["retryable"])
    except (ValueError, KeyError, TypeError):
        # A response we cannot parse is not something to record against a
        # crash; treat it as transient and let the next tick try again.
        raise DecodeUnavailable(
            f"debug service returned HTTP {response.status_code}") from None

    if retryable:
        raise DecodeUnavailable(message)
    raise DecodePermanent(message)


def _timeout():
    try:
        return int(os.environ.get("DECODE_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS))
    except ValueError:
        return DEFAULT_TIMEOUT_SECONDS


def log_result(crash_id, result):
    """One audit line per decode, so a toolchain fallback or a multi-build
    version is visible in the cron log rather than only in the stored text."""
    current_app.logger.info(
        "Decoded crash %s via %s (%s)%s: %s module(s), %s builds match",
        crash_id, result.get("toolchain"), result.get("toolchain_source"),
        f", build {result['elf_file_id']}" if result.get("elf_file_id") else "",
        len(result.get("modules") or []), result.get("elf_count"),
    )
