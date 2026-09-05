"""Turn a stored crash into a directory a jailed debugger can open.

Everything a debugger needs is already in Postgres as bz2-compressed BYTEA -
the raw crash artifact, the build ELF, and debug symbols for any
runtime-loaded modules. There is no object store and no bundle: a session's
work directory is built here, straight from those blobs.

The split of responsibility matters. This module runs in the *service* process,
which holds the database credentials; the jails it drives have `--unshare-net`
and see only the work directory, so the debugger never has database access or a
network. That is the whole reason materialization happens here rather than
inside the sandbox.

What each step *does* comes from the toolchain descriptor, not from this file.
Nothing here knows what Espressif is, what a coredump partition image is, or
that the debugger is gdb: it renders the descriptor's commands and runs them in
the right jail tier. A target whose artifact is already a core file declares no
`core` phase; one with no runtime modules declares no `modules` section; and
both work without a branch here.
"""
import bz2
import os
import re
import shutil

from gdb_app import jail, modreg

# Names inside the work directory (which is bound at /work in the jail, so
# these double as the jail-relative paths handed to the debugger).
DUMP = "core.dmp"
PROG = "prog.elf"
CORE = "core.elf"
SYMBOLS_FILE = "module_symbols.gdbinit"
MODULE_DIR = "modules"

# Module names come out of an attacker-influenced artifact and become path
# components, so they are reduced to a known-safe alphabet.
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")

# Registry protocols this server can drive. A descriptor names one; resolving a
# name must not become an arbitrary import.
REGISTRY_PROTOCOLS = {"esp_crash_modmap"}


class SandboxUnavailable(Exception):
    """The sandbox itself could not be started.

    Emphatically not a property of the artifact, and the distinction is
    load-bearing: treated as a bad dump it gets written into `crash.dump` and
    the row is marked processed forever. That is exactly what happened when
    zombie bwrap processes exhausted the batch accounts' RLIMIT_NPROC - 242
    real crashes had "bwrap: Can't fork for pid 1" stored as their backtrace,
    permanently, because a transient resource failure was reported as
    convert_failed. Callers must retry this rather than record it.
    """


def _sandbox_failed(text):
    """Whether bwrap reported that it could not build the sandbox.

    bwrap writes its own diagnostics with a `bwrap: ` prefix and they reach us
    on the phase's captured output; the jailed command never gets to run, so
    anything else in that output is absent rather than misleading.
    """
    return any(line.startswith("bwrap: ")
               for line in (text or "").splitlines())


class NotDebuggable(Exception):
    """The crash cannot be debugged, with a reason meant for the user.

    Distinct from an internal error: every case is a legitimate state of the
    data (no build uploaded, no toolchain configured, an artifact that will not
    convert) that the person asking can usually act on, so the message is
    written for them.
    """


def maybe_bunzip(blob):
    """Normalise a stored blob. Rows are bz2-compressed, but historically some
    were stored raw, so every read path in this codebase tries decompression
    and falls back."""
    try:
        return bz2.decompress(blob)
    except (IOError, OSError, ValueError):
        return blob


def grant_to_session(path, gid):
    """Make `path` readable by the session's jail, keeping root as owner.

    Explicit rather than inherited: a setgid work directory would be tidier,
    but the service holds no CAP_FSETID, so the kernel strips the setgid bit and
    files silently land in group root - where the jail, running as the session
    uid, cannot read them. The symptom is the debugger reporting "No such file
    or directory" for a file that is plainly there.
    """
    os.chown(path, 0, gid)
    os.chmod(path, 0o750 if os.path.isdir(path) else 0o640)


def grant_tree_to_session(root, gid):
    """Apply `grant_to_session` to everything under `root` still owned by us -
    covering files a conversion step produced in the service process. Files a
    *jailed* step created already belong to the session uid."""
    for dirpath, dirnames, filenames in os.walk(root):
        for name in list(dirnames) + list(filenames):
            path = os.path.join(dirpath, name)
            try:
                if os.stat(path).st_uid == 0:
                    grant_to_session(path, gid)
            except OSError:
                pass


def _write(work, name, data, gid):
    path = os.path.join(work, name)
    with open(path, "wb") as f:
        f.write(data)
    grant_to_session(path, gid)
    return path


class Prepared:
    """The result of materialization.

    The three text fields are kept apart rather than concatenated into one log,
    because callers want different things: an interactive session shows the
    symbolicated report as its preamble, while the batch decode stores it. A
    single list forced callers to depend on element order.
    """

    def __init__(self, argv, convert_log="", module_notes=(), report="", modules=()):
        self.argv = argv
        self.convert_log = convert_log
        self.module_notes = tuple(module_notes)
        self.report = report
        self.modules = list(modules)

    def preamble(self):
        """What to show before handing over an interactive terminal: which
        module symbols resolved, then the report itself. Falls back to the
        conversion output when a toolchain declares no report phase."""
        parts = list(self.module_notes)
        parts.append(self.report or self.convert_log)
        return "".join(p if p.endswith("\n") else p + "\n" for p in parts if p.strip())


def prepare(artifacts, toolchain, lease, get_module_elf):
    """Populate `lease.workdir` and return a `Prepared`.

    `get_module_elf(sha1) -> bytes | None` is injected rather than imported so
    this module needs no Flask app context of its own: the caller already holds
    one for the ACL-scoped lookups.
    """
    work = lease.workdir

    if not artifacts.get("dump"):
        raise NotDebuggable("This crash has no dump data stored.")
    if "prog" in (toolchain.requires or ()) and not artifacts.get("prog"):
        raise NotDebuggable(
            f"No build (ELF) has been uploaded for {artifacts['project_name']} "
            f"version {artifacts['project_ver']}, so there are no symbols to "
            f"debug with.")

    _write(work, DUMP, maybe_bunzip(artifacts["dump"]), lease.gid)
    if artifacts.get("prog"):
        _write(work, PROG, maybe_bunzip(artifacts["prog"]), lease.gid)

    subst = {
        "root": toolchain.root or "",
        "debugger": toolchain.exe,
        "python": toolchain.python or "",
        "dump": DUMP, "prog": PROG, "core": CORE,
        "symbols_file": SYMBOLS_FILE, "work": jail.WORK,
        "chip": toolchain.chip or "",
    }

    convert = _spec(toolchain, work, lease, jail.CONVERT)
    convert_log = _make_core(toolchain, subst, convert, work, lease)

    # Extra symbol sources first: they are derived from the core, and unlike
    # module symbols they need no registry read.
    extra_symbols, extra_notes = _extra_symbols(toolchain, subst, convert)

    modules, notes, module_symbols = _load_modules(
        toolchain, subst, work, lease, get_module_elf)

    commands = list(extra_symbols) + list(module_symbols)
    if commands:
        _write(work, SYMBOLS_FILE, ("\n".join(commands) + "\n").encode(), lease.gid)

    report = _make_report(toolchain, subst, convert, convert_log, modules,
                          with_symbols=bool(commands))

    # Gated on the file having content rather than on modules alone: a
    # toolchain can contribute symbols with no runtime modules in play at all,
    # which is the usual case for a chip ROM.
    argv = toolchain.render(toolchain.interactive, subst,
                            with_symbols=bool(commands))[0]
    return Prepared(argv, convert_log=convert_log,
                    module_notes=extra_notes + notes,
                    report=report, modules=modules)


def _spec(toolchain, work, lease, tier):
    return jail.JailSpec(toolchain=toolchain, workdir=work,
                         uid=lease.uid, gid=lease.gid, tier=tier)


def _make_core(toolchain, subst, convert, work, lease):
    """Produce the file the debugger opens.

    A toolchain that declares no `core` phase is saying its artifact already is
    that file - which is what the old `passthrough` converter was, now expressed
    as an absence rather than a plugin.
    """
    if toolchain.core is None:
        shutil.copyfile(os.path.join(work, DUMP), os.path.join(work, CORE))
        grant_to_session(os.path.join(work, CORE), lease.gid)
        return "# artifact used directly as a core file (no conversion needed)\n"

    log = ""
    for argv in toolchain.render(toolchain.core, subst):
        result = jail.run_batch(convert, argv, timeout=toolchain.core.timeout)
        log += (result.stdout or b"").decode("utf-8", "replace")
    grant_tree_to_session(work, lease.gid)

    if not os.path.exists(os.path.join(work, CORE)):
        if _sandbox_failed(log):
            raise SandboxUnavailable(
                "The debug sandbox could not be started, so this crash was not "
                "decoded.\n\n" + log)
        raise NotDebuggable(
            "The crash dump could not be converted into a core file. It may be "
            "truncated, or from a firmware version this toolchain cannot read."
            "\n\n" + log)
    return log


def _make_report(toolchain, subst, convert, convert_log, modules, with_symbols=False):
    """Produce the human-readable report.

    A second pass can only do something the conversion pass could not: resolve
    module frames. So it is skipped when no module symbols were staged - its
    output would be the conversion pass's own bytes, arrived at again over
    several seconds. The batch decode has always made this distinction, and most
    crashes have no runtime modules at all.

    When modules *are* staged the pass runs, even though it sometimes still
    produces identical text - a crash whose frames all fall in the main
    application needs none of the module symbols. There is no way to know that
    without symbolicating, so the cost is inherent rather than wasteful.
    """
    if toolchain.report is None:
        return convert_log
    if not modules and toolchain.core is not None:
        return convert_log

    report = ""
    for argv in toolchain.render(toolchain.report, subst, with_symbols=with_symbols):
        result = jail.run_batch(convert, argv, timeout=toolchain.report.timeout)
        report += (result.stdout or b"").decode("utf-8", "replace")
    if _sandbox_failed(report):
        # The conversion succeeded, so the artifact is fine; storing this text
        # as the backtrace would mark a decodable crash permanently broken.
        raise SandboxUnavailable(
            "The debug sandbox could not be started for the report pass.\n\n"
            + report)
    return report


def _extra_symbols(toolchain, subst, convert):
    """Debugger commands for symbol sources that are neither the build ELF nor
    a runtime-loaded module - a chip's ROM being the case that prompted this.

    The declared commands print debugger script on stdout and we collect it
    verbatim. Which ROM image applies depends on the chip revision recorded in
    the core, so this cannot be a static path in the descriptor; running a
    command the package ships keeps that knowledge with the toolchain that has
    it instead of in this module.

    Best-effort, exactly like module symbols: a failure costs some frames their
    names, which is not a reason to refuse a session.
    """
    if toolchain.symbols is None:
        return (), ()

    commands, notes = [], []
    for argv in toolchain.render(toolchain.symbols, subst):
        try:
            result = jail.run_batch(convert, argv, timeout=toolchain.symbols.timeout)
        except Exception as e:                   # noqa: BLE001
            notes.append(f"# extra symbols: {e}\n")
            continue
        out = (result.stdout or b"").decode("utf-8", "replace")
        commands += [line for line in (l.strip() for l in out.splitlines()) if line]
    # Nothing is reported on success. The note would head every stored report
    # with "extra symbol sources loaded: 1" - a count with no subject, ahead of
    # the backtrace someone actually opened the page for. A failure still says
    # so, because that one explains missing frame names.
    return tuple(commands), tuple(notes)


def _load_modules(toolchain, subst, work, lease, get_module_elf):
    """Read the on-device module registry and stage symbols for every module we
    have them for.

    Best-effort by design. A toolchain that declares no `modules` section skips
    this entirely; a firmware that loads none has no registry symbol and yields
    an empty list; a module whose symbols were never uploaded simply keeps
    unresolved frames. None of those is a reason to refuse a session - the main
    backtrace is still useful.
    """
    spec = toolchain.modules
    if spec is None:
        return [], (), ()
    if spec.registry not in REGISTRY_PROTOCOLS:
        return [], (f"# unknown module registry protocol {spec.registry!r}; "
                    f"module symbols not resolved\n",), ()

    session = _spec(toolchain, work, lease, jail.SESSION)
    batch = [a.format(**subst) for a in spec.batch]

    def runner(commands):
        argv = list(batch)
        for command in commands:
            argv += ["-ex", command]
        result = jail.run_batch(session, argv, timeout=120)
        return (result.stdout or b"").decode("utf-8", "replace")

    try:
        registry = modreg.read_registry(runner)
    except Exception as e:                       # noqa: BLE001
        return [], (f"# could not read the module registry: {e}\n",), ()

    module_dir = os.path.join(work, MODULE_DIR)
    os.makedirs(module_dir, mode=0o750, exist_ok=True)
    grant_to_session(module_dir, lease.gid)

    loaded, notes = [], []
    for entry in registry:
        sha1 = entry.get("sha1", "")
        blob = get_module_elf(sha1)
        ident = f"{entry['name']} (sha1 {sha1[:8]}...)"
        if blob is None:
            notes.append(f"# module {ident}: symbols not available\n")
            continue
        rel = os.path.join(MODULE_DIR, f"{_UNSAFE.sub('_', entry['name'])}.elf")
        _write(work, rel, maybe_bunzip(blob), lease.gid)
        loaded.append({**entry, "elf": rel})
        notes.append(f"# module {ident}: symbols loaded\n")

    commands = ()
    if loaded and spec.add_symbols:
        # The debugger's syntax for this comes from the descriptor; paths are
        # jail-relative and the debugger runs with /work as its cwd. The file
        # itself is written by prepare(), which merges these with any extra
        # symbol sources so the debugger loads one script.
        commands = tuple(modreg.render_add_symbols(spec.add_symbols, loaded))
    return loaded, tuple(notes), commands
