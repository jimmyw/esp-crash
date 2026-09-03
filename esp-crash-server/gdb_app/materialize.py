"""Turn a stored crash into a directory a jailed debugger can open.

Everything gdb needs is already in Postgres as bz2-compressed BYTEA - the raw
crash dump, the build ELF, and the debug symbols for any runtime-loaded
modules. There is no object store and no bundle: a session's work directory is
built here, straight from those blobs.

The split of responsibility matters. This module runs in the *service* process,
which holds the database credentials; the jails it drives have `--unshare-net`
and see only the work directory, so the debugger never has database access or
a network. That is the whole reason materialization happens here rather than
inside the sandbox.

The pipeline mirrors what `app/routes/crashes.py:download_crash` assembles for
offline debugging and what `app/routes/cron.py` does for the stored backtrace,
and it reuses the same helpers from `decode_module_coredump` so the gdb command
formats live in exactly one place.
"""
import bz2
import os
import re

import decode_module_coredump as mod_decoder

from . import converters, jail

# Names inside the work directory (which is bound at /work in the jail, so
# these double as the jail-relative paths handed to gdb).
DUMP = "core.dmp"
PROG = "prog.elf"
CORE = "core.elf"
GDBINIT = "module_symbols.gdbinit"
MODULE_DIR = "modules"

# Module names come out of an attacker-influenced coredump and become path
# components, so they are reduced to a known-safe alphabet - the same guard
# app/routes/crashes.py:221 applies before putting one in a zip entry name.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")


class NotDebuggable(Exception):
    """The crash cannot be debugged, with a reason meant for the user.

    Distinct from an internal error: every case here is a legitimate state of
    the data (no build uploaded yet, no toolchain configured) that the person
    asking can usually act on, so the message is written for them.
    """


def maybe_bunzip(blob):
    """Normalise a stored blob. Rows are bz2-compressed, but historically some
    were stored raw, so every read path in this codebase tries decompression
    and falls back - see app/routes/cron.py and download_crash."""
    try:
        return bz2.decompress(blob)
    except (IOError, OSError, ValueError):
        return blob


def _write(work, name, data, gid):
    path = os.path.join(work, name)
    with open(path, "wb") as f:
        f.write(data)
    grant_to_session(path, gid)
    return path


def grant_to_session(path, gid):
    """Make `path` readable by the session's jail, keeping root as owner.

    Explicit rather than inherited: a setgid work directory would be the tidier
    mechanism, but the service holds no CAP_FSETID (it runs with almost every
    capability dropped), so the kernel strips the setgid bit and files silently
    land in group root - where the jail, running as the session uid, cannot
    read them. The symptom is gdb reporting "No such file or directory" for a
    file that is plainly there.
    """
    os.chown(path, 0, gid)
    os.chmod(path, 0o750 if os.path.isdir(path) else 0o640)


def grant_tree_to_session(root, gid):
    """Apply `grant_to_session` to everything under `root` still owned by us.

    Covers files a converter produced in the service process (the passthrough
    converter copies rather than executing anything). Files a *jailed*
    converter created already belong to the session uid and are left alone.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + list(filenames):
            path = os.path.join(dirpath, name)
            try:
                if os.stat(path).st_uid == 0:
                    grant_to_session(path, gid)
            except OSError:
                pass


class Prepared:
    """The result of materialization: the argv to run in the session jail, plus
    log lines describing what symbols were and were not available."""

    def __init__(self, argv, log, modules):
        self.argv = argv
        self.log = log
        self.modules = modules


def prepare(artifacts, toolchain, lease, get_module_elf, convert_timeout=180):
    """Populate `lease.workdir` and return a `Prepared` for the session jail.

    `get_module_elf(sha1) -> bytes | None` is injected rather than imported so
    this module needs no Flask app context of its own: the caller already holds
    one for the ACL-scoped lookups.
    """
    work = lease.workdir
    log = []

    if not artifacts.get("dump"):
        raise NotDebuggable("This crash has no dump data stored.")
    if not artifacts.get("prog"):
        raise NotDebuggable(
            f"No build (ELF) has been uploaded for {artifacts['project_name']} "
            f"version {artifacts['project_ver']}, so there are no symbols to "
            f"debug with.")

    _write(work, DUMP, maybe_bunzip(artifacts["dump"]), lease.gid)
    _write(work, PROG, maybe_bunzip(artifacts["prog"]), lease.gid)

    # --- conversion tier: parse the untrusted artifact into a core gdb can open
    converter = converters.get(toolchain.converter)
    convert_spec = jail.JailSpec(
        toolchain=toolchain, workdir=work, uid=lease.uid, gid=lease.gid,
        tier=jail.CONVERT, extra_ro=converter.extra_ro_binds(),
    )

    def run_convert(command, timeout=convert_timeout):
        return jail.run_batch(convert_spec, command, timeout=timeout)

    log.append(converter.convert(run_convert, toolchain, DUMP, PROG, CORE, work=work))
    grant_tree_to_session(work, lease.gid)
    if not os.path.exists(os.path.join(work, CORE)):
        raise NotDebuggable(
            "The crash dump could not be converted into a core file. "
            "It may be truncated or from an incompatible firmware version.\n\n"
            + "".join(log))

    # --- session tier from here on: plain gdb, no interpreter, no converter
    session_spec = jail.JailSpec(
        toolchain=toolchain, workdir=work, uid=lease.uid, gid=lease.gid,
        tier=jail.SESSION,
    )

    modules = _load_modules(session_spec, toolchain, work, get_module_elf, log,
                            lease.gid)

    argv = [toolchain.exe, "-nx", "-q", PROG, "-ex", f"core-file {CORE}"]
    if modules:
        argv += ["-x", GDBINIT]
    return Prepared(argv, log, modules)


def _load_modules(session_spec, toolchain, work, get_module_elf, log, gid):
    """Read the on-device module registry out of the core and stage debug
    symbols for every module we have them for.

    Best-effort by design: a firmware that loads no modules has no `s_mod_map`
    symbol and `read_registry` returns an empty list, and a module whose
    symbols were never uploaded simply keeps unresolved frames. Neither is a
    reason to refuse a session - the main backtrace is still useful.
    """
    def runner(commands):
        """Execute gdb commands against (PROG, CORE) inside the session jail.

        Passed to read_registry so the two-pass `printf` line protocol it
        implements is reused rather than reimplemented here.
        """
        argv = [toolchain.exe, "-batch", "-nx", PROG, "-ex", f"core-file {CORE}"]
        for c in commands:
            argv += ["-ex", c]
        result = jail.run_batch(session_spec, argv, timeout=120)
        return (result.stdout or b"").decode("utf-8", "replace")

    try:
        registry = mod_decoder.read_registry(CORE, PROG, runner=runner)
    except Exception as e:                       # noqa: BLE001
        log.append(f"# could not read the module registry: {e}\n")
        return []

    module_dir = os.path.join(work, MODULE_DIR)
    os.makedirs(module_dir, mode=0o750, exist_ok=True)
    grant_to_session(module_dir, gid)

    loaded = []
    for entry in registry:
        sha1 = entry.get("sha1", "")
        blob = get_module_elf(sha1)
        ident = f"{entry['name']} (sha1 {sha1[:8]}...)"
        if blob is None:
            log.append(f"# module {ident}: symbols not available\n")
            continue
        rel = os.path.join(MODULE_DIR, f"{_UNSAFE.sub('_', entry['name'])}.elf")
        _write(work, rel, maybe_bunzip(blob), gid)
        loaded.append({**entry, "elf": rel})
        log.append(f"# module {ident}: symbols loaded\n")

    if loaded:
        # addsym_commands() emits the literal `add-symbol-file <elf> <addr>
        # -s .data ...` lines; the paths are jail-relative and gdb runs with
        # /work as its cwd, so they resolve inside the sandbox.
        _write(work, GDBINIT,
               ("\n".join(mod_decoder.addsym_commands(loaded)) + "\n").encode(),
               gid)
    return loaded
