"""Batch crash decoding, for the pre-analysis that cron performs.

The interactive session and the batch decode want the same work done - convert
the artifact, resolve module symbols, produce a report - so they share
`materialize.prepare`. What differs is only what happens afterwards: a session
attaches a pty, while this returns the text and lets the caller store it.

This endpoint deliberately performs **no database writes**. Cron keeps ownership
of the crash row and of the ordering that follows a decode (signature, relation
upsert, webhooks, Slack) in its own transaction. That also keeps this
idempotent and side-effect-free, which is what makes it safe to run against
production rows when comparing old and new reports.

The signature is likewise not computed here. `app/crash_signature.py` is
grouping *policy* - it parses the report's text and is also run standalone over
already-stored dumps - so a second implementation living in the sandboxed
service would have to agree with that one forever, and changing a hashing rule
would mean redeploying a privileged container.
"""
import os
import time

import toolchains
from gdb_app import materialize
from gdb_app.uidpool import PoolExhausted

# Used when a project has no toolchain configured. Not an arbitrary default: it
# reproduces what the previous in-process decode resolved to for *every*
# project, since `decode_module_coredump.find_gdb()` picked
# `xtensa-esp32-elf-gdb` off PATH regardless of the project. Without it, moving
# cron to this endpoint would silently stop decoding for every project that has
# not set the column - which, when this was written, was eight of the ten
# projects that have crashes.
DEFAULT_TOOLCHAIN_ENV = "GDB_DEFAULT_TOOLCHAIN"


class DecodeError(Exception):
    """A decode could not be produced, with a code the caller can act on.

    `retryable` is load-bearing. A permanent failure is stored as the crash's
    dump so it stops being reprocessed every tick (matching the old behaviour,
    where `# esp-coredump unavailable: ...` got stored); a retryable one must
    leave the row alone. Getting that backwards for `no_toolchain` would write
    error text into thousands of rows.
    """

    def __init__(self, code, message, *, retryable, status=422):
        super().__init__(message)
        self.code = code
        self.message = message
        self.retryable = retryable
        self.status = status

    def as_dict(self):
        return {"error": {"code": self.code, "message": self.message,
                          "retryable": self.retryable}}


def resolve_toolchain(name):
    """Pick the toolchain for a crash, falling back to the configured default.

    Returns `(toolchain, source)` where source is "project" or "default", so a
    caller can tell which crashes are relying on the fallback.
    """
    if name:
        tc = toolchains.get(name)
        if tc is None:
            raise DecodeError(
                "no_toolchain",
                f"Toolchain {name!r} is configured for this project but is not "
                f"installed on this server (available: "
                f"{', '.join(toolchains.names()) or 'none'}).",
                retryable=True)
        return tc, "project"

    default = os.environ.get(DEFAULT_TOOLCHAIN_ENV)
    tc = toolchains.get(default) if default else None
    if tc is None:
        raise DecodeError(
            "no_toolchain",
            "No toolchain is configured for this project and no server default "
            f"is available (available: {', '.join(toolchains.names()) or 'none'}).",
            retryable=True)
    return tc, "default"


def decode(artifacts, pool, get_module_elf, logger=None):
    """Decode one crash and return what the caller needs in order to store it.

    `artifacts` comes from `mcp_app.service_reads.get_decode_artifacts`; `pool`
    is the batch identity pool, kept disjoint from the interactive one so a
    decode backlog cannot take a slot an actual person is waiting for.
    """
    started = time.monotonic()
    if not artifacts.get("dump"):
        raise DecodeError("no_dump", "This crash has no dump data stored.",
                          retryable=False)

    toolchain, source = resolve_toolchain(artifacts.get("toolchain"))

    if "prog" in (toolchain.requires or ()) and not artifacts.get("prog"):
        raise DecodeError(
            "no_build",
            f"No build has been uploaded for {artifacts['project_name']} "
            f"version {artifacts['project_ver']}.",
            retryable=True)

    try:
        lease = pool.acquire_sync()
    except PoolExhausted as e:
        raise DecodeError("busy", str(e), retryable=True, status=503) from None

    try:
        try:
            prepared = materialize.prepare(artifacts, toolchain, lease, get_module_elf)
        except materialize.SandboxUnavailable as e:
            # Our side failed, not the artifact. Retryable, and deliberately
            # checked before NotDebuggable: recording this would write the
            # sandbox's diagnostics into the crash's backtrace and mark it
            # processed for good.
            raise DecodeError("sandbox_unavailable", str(e),
                              retryable=True, status=503) from None
        except materialize.NotDebuggable as e:
            # The artifact itself will not decode. Permanent: reprocessing it
            # every tick would achieve nothing.
            raise DecodeError("convert_failed", str(e), retryable=False) from None

        report = prepared.preamble()
        notes = []
        if (artifacts.get("elf_count") or 0) > 1:
            # The previous batch path ran once per matching build and
            # concatenated a report each time, which left module_map describing
            # the oldest build while the signature came from the newest. One
            # build is used now; say which, at the *end* so the webhook and
            # Slack snippets (dump[:500]) are unchanged.
            note = (f"\n# note: {artifacts['elf_count']} builds match version "
                    f"{artifacts['project_ver']}; symbolicated against build "
                    f"{artifacts['elf_file_id']}"
                    + (f" (uploaded {artifacts['elf_date'][:10]})"
                       if artifacts.get("elf_date") else "")
                    + ".\n")
            notes.append(note.strip())
            report = report + note

        duration_ms = int((time.monotonic() - started) * 1000)
        if logger:
            logger.info(
                "decoded crash %s: toolchain=%s (%s) build=%s modules=%s "
                "report=%sB in %sms",
                artifacts["crash_id"], toolchain.name, source,
                artifacts.get("elf_file_id"), len(prepared.modules),
                len(report), duration_ms)

        return {
            "crash_id": artifacts["crash_id"],
            "report": report,
            # Section addresses are included so the crash-zip download can emit
            # symbol-loading commands without a debugger of its own.
            "modules": [
                {k: v for k, v in module.items() if k != "elf"} | {"symbols": True}
                for module in prepared.modules
            ],
            "module_names": [m["name"] for m in prepared.modules],
            "toolchain": toolchain.name,
            "toolchain_source": source,
            "elf_file_id": artifacts.get("elf_file_id"),
            "elf_count": artifacts.get("elf_count"),
            "notes": notes,
            "duration_ms": duration_ms,
        }
    finally:
        pool.release_sync(lease)
