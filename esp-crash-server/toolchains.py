"""Installed debugger toolchains, discovered at runtime from mounted packages.

A *toolchain* is everything needed to debug one target: a debugger, the exact
libraries and data files it needs, optionally its own interpreter, and
instructions for turning a raw crash artifact into a core file, a report, and an
interactive session.

Toolchains arrive as **packages** - self-contained directories built by
`toolchains/recipes/` and mounted read-only - each carrying a `toolchain.yml`
describing itself. Nothing here is baked into the image, so adding support for a
chip family is dropping in a directory rather than rebuilding and redeploying.

Deliberately vendor-neutral. Nothing in this module knows what Espressif is: the
debugger's name, its environment, the commands that produce a core and a report,
the debugger syntax for loading module symbols - all of it is descriptor data.
An `arm-none-eabi` package that needs no conversion and has no module registry
is expressed by *omitting* those sections, not by adding code here.

Kept as a top-level module (like `decode_module_coredump` and `device_url`)
rather than inside `app/`: it is pure logic with no Flask dependency, and both
the web app and the standalone debug service import it.

"""
import functools
import glob
import os
import string
import subprocess
from dataclasses import dataclass, field

import yaml

# Where packages are mounted, colon-separated. Nothing is baked into the image
# any more, so an empty directory here means no toolchains and no debugging -
# which both the settings page and the service report plainly.
DEFAULT_ROOTS = "/opt/toolchains"

DESCRIPTOR_NAME = "toolchain.yml"

SCHEMA_VERSION = 1

# The placeholder set is the interface between this service and a descriptor, so
# it is closed: an unrecognised placeholder is a load error, never a literal
# that reaches a command line and fails somewhere far away.
PLACEHOLDERS = frozenset({
    "root", "debugger", "python", "dump", "prog", "core", "symbols_file", "work",
    # The variant's declared chip, for a toolchain whose extra symbol sources
    # are per-chip (Espressif's ROM ELFs). Empty when the descriptor declares
    # no chip, so a command using it is only meaningful where one is set.
    "chip",
})
# Additionally allowed inside `modules.add_symbols`, where the values come from
# the on-device module registry.
MODULE_PLACEHOLDERS = frozenset({
    "elf", "name", "version", "sha1", "text", "data", "bss", "rodata",
})


class DescriptorError(ValueError):
    """A descriptor is malformed. Always names the file and the problem: these
    are read at runtime from a mounted directory, so a bad one must be loud
    rather than yield a half-configured sandbox.

    A ValueError because that is what it is, and because callers already
    treated a bad manifest that way.
    """


@dataclass(frozen=True)
class Phase:
    """One declared step: a list of argv templates run in order."""
    commands: tuple = ()
    # Appended to the final command only once module symbols were resolved.
    with_symbols: tuple = ()
    timeout: int = 300


@dataclass(frozen=True)
class Modules:
    """How to enumerate runtime-loaded modules and hand their symbols to the
    debugger. Absent for a target that has none.

    `registry` names an in-tree parsing protocol rather than describing one:
    that part is genuinely code (a debugger `printf` line protocol), and
    resolving a name must not become an arbitrary import - see
    `gdb_app.modreg`.
    """
    registry: str
    batch: tuple = ()
    add_symbols: tuple = ()


@dataclass(frozen=True)
class Toolchain:
    """One selectable toolchain, as stored in `project_settings.toolchain`."""
    name: str
    arch: str
    version: str
    exe: str
    root: str = None                    # the package directory
    python: str = None                  # the package's own interpreter, if any
    chip: str = None
    description: str = ""
    env: dict = field(default_factory=dict)
    binds: tuple = ()                   # declared paths outside the package
    library_path: tuple = ()
    requires: tuple = ()
    core: Phase = None
    report: Phase = None
    interactive: Phase = None
    # Optional. Commands whose stdout is debugger script, loaded alongside any
    # module symbols - for symbol sources that are neither the build ELF nor a
    # runtime-loaded module, such as a chip's ROM.
    symbols: Phase = None
    modules: Modules = None

    @property
    def ro_binds(self):
        """Every host path this toolchain needs bound read-only.

        The package directory itself, the declared binds, and the library
        closure - computed here rather than recorded at build time
        because the closure is a property of the *runtime* image. A package
        built on Arch resolves `/usr/lib/libc.so.6`; the Debian-based server
        image needs `/lib/x86_64-linux-gnu/libc.so.6`. Recording it at build
        time would bake in the build host's paths.

        Computed lazily and cached: the web app calls `installed()` on every
        crash-page render and needs only names and versions, so it must never
        pay for this.
        """
        return _package_binds(self.root, self.exe, self.python, self.binds,
                              _tree_signature(self.root))

    def render(self, phase, subst, with_symbols=False):
        """Substitute placeholders into a phase's commands, returning a list of
        argv lists.

        Substitution is per-argv-element over a list, never a shell string, so
        no value can inject an argument.
        """
        if phase is None:
            return []
        out = []
        for i, argv in enumerate(phase.commands):
            rendered = [a.format(**subst) for a in argv]
            if with_symbols and i == len(phase.commands) - 1:
                rendered += [a.format(**subst) for a in phase.with_symbols]
            out.append(rendered)
        return out


# --------------------------------------------------------------------- loading

def _require(spec, key, where):
    value = spec.get(key)
    if not value:
        raise DescriptorError(f"{where}: missing required key {key!r}")
    return value


def _resolve(root, value, where, what):
    """Resolve a descriptor path: relative to the package unless absolute.

    Refuses to escape the package. Defence in depth behind the read-only mount,
    not a substitute for it - the toolchains directory is as trusted as the
    image was, since a descriptor names commands to execute.
    """
    path = value if os.path.isabs(value) else os.path.join(root, value)
    real = os.path.realpath(path)
    if not os.path.isabs(value) and not real.startswith(os.path.realpath(root) + os.sep):
        raise DescriptorError(f"{where}: {what} {value!r} escapes the package directory")
    return real


def _check_placeholders(argv, allowed, where):
    for element in argv:
        if not isinstance(element, str):
            raise DescriptorError(
                f"{where}: every command element must be a string, got {element!r} "
                f"(a command is a list of arguments, not a shell string)")
        for _lit, fieldname, _spec, _conv in string.Formatter().parse(element):
            if fieldname is None:
                continue
            base = fieldname.split(".")[0].split("[")[0]
            if base not in allowed:
                raise DescriptorError(
                    f"{where}: unknown placeholder {{{fieldname}}} "
                    f"(known: {', '.join(sorted(allowed))})")


def _phase(spec, key, allowed, where, single=False):
    section = spec.get(key)
    if section is None:
        return None
    if not isinstance(section, dict):
        raise DescriptorError(f"{where}: {key} must be a mapping")

    if single:
        command = section.get("command")
        if not command:
            raise DescriptorError(f"{where}: {key}.command is required")
        commands = [command]
    else:
        commands = section.get("commands")
        if not commands:
            raise DescriptorError(f"{where}: {key} is declared but has no commands")
        if not isinstance(commands, list) or not all(isinstance(c, list) for c in commands):
            raise DescriptorError(f"{where}: {key}.commands must be a list of argv lists")

    for i, argv in enumerate(commands):
        _check_placeholders(argv, allowed, f"{where}: {key}.commands[{i}]")
    with_symbols = tuple(section.get("with_symbols") or ())
    _check_placeholders(with_symbols, allowed, f"{where}: {key}.with_symbols")

    return Phase(commands=tuple(tuple(c) for c in commands),
                 with_symbols=with_symbols,
                 timeout=int(section.get("timeout", 300)))


def _load_descriptor(path):
    """Parse one `toolchain.yml` into one Toolchain per declared variant."""
    where = path
    with open(path) as f:
        spec = yaml.safe_load(f)
    if not isinstance(spec, dict):
        raise DescriptorError(f"{where}: must be a mapping")

    schema = spec.get("schema")
    if schema != SCHEMA_VERSION:
        raise DescriptorError(
            f"{where}: unsupported schema {schema!r} (this server understands "
            f"{SCHEMA_VERSION})")

    root = os.path.realpath(os.path.dirname(path))
    name = _require(spec, "name", where)
    arch = _require(spec, "arch", where)
    version = str(_require(spec, "version", where))

    exe = _resolve(root, _require(spec, "debugger", where), where, "debugger")
    python = spec.get("python")
    python = _resolve(root, python, where, "python") if python else None

    allowed = set(PLACEHOLDERS)
    if python is None:
        allowed.discard("python")

    core = _phase(spec, "core", allowed, where)
    report = _phase(spec, "report", allowed, where)
    symbols = _phase(spec, "symbols", allowed, where)
    interactive = _phase(spec, "interactive", allowed, where, single=True)
    if interactive is None:
        raise DescriptorError(
            f"{where}: interactive.command is required - it is what the pty attaches to")

    modules = None
    if (msec := spec.get("modules")) is not None:
        if not isinstance(msec, dict):
            raise DescriptorError(f"{where}: modules must be a mapping")
        batch = tuple(msec.get("batch") or ())
        add_symbols = tuple(msec.get("add_symbols") or ())
        _check_placeholders(batch, allowed, f"{where}: modules.batch")
        _check_placeholders(add_symbols, allowed | MODULE_PLACEHOLDERS,
                            f"{where}: modules.add_symbols")
        modules = Modules(registry=_require(msec, "registry", f"{where}: modules"),
                          batch=batch, add_symbols=add_symbols)

    def expand(value):
        return value.replace("{root}", root) if isinstance(value, str) else value

    base_env = {k: expand(v) for k, v in (spec.get("env") or {}).items()}
    binds = tuple(expand(b) for b in (spec.get("binds") or ()))
    library_path = tuple(expand(p) for p in (spec.get("library_path") or ()))
    requires = tuple(spec.get("requires") or ())

    def build(tc_name, chip, extra_env):
        return Toolchain(
            name=tc_name, arch=arch, version=version, exe=exe, root=root,
            python=python, chip=chip, description=(spec.get("description") or "").strip(),
            env={**base_env, **extra_env}, binds=binds, library_path=library_path,
            requires=requires, core=core, report=report, interactive=interactive,
            symbols=symbols, modules=modules,
        )

    variants = spec.get("variants")
    if not variants:
        return [build(name, spec.get("chip"), {})]
    if not isinstance(variants, dict):
        raise DescriptorError(f"{where}: variants must be a mapping of id -> settings")

    out = []
    for vid, variant in variants.items():
        variant = variant or {}
        out.append(build(vid, variant.get("chip"),
                         {k: expand(v) for k, v in (variant.get("env") or {}).items()}))
    return out


# ------------------------------------------------------------------- discovery

def roots():
    return [r for r in os.environ.get("GDB_TOOLCHAIN_ROOTS", DEFAULT_ROOTS).split(":") if r]


def _signature(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


@functools.lru_cache(maxsize=64)
def _parse(path, _signature_key):
    return tuple(_load_descriptor(path))


def _tree_signature(root):
    """A cheap fingerprint of a package, used to invalidate the cached library
    closure. The descriptor's own mtime is not enough: replacing a binary in
    place would keep it while changing what the closure should be."""
    newest = 0
    for dirpath, _dirs, files in os.walk(root):
        for name in (*files, ""):
            try:
                newest = max(newest, os.stat(os.path.join(dirpath, name)).st_mtime_ns)
            except OSError:
                continue
    return newest


def discover():
    """Scan the configured roots. Uncached at this level on purpose - a package
    dropped into the mount must be visible without restarting anything - but
    each file's *parse* is cached by its signature, so a scan is a handful of
    stat calls."""
    found = {}
    for root in roots():
        for path in sorted(glob.glob(
                os.path.join(root, "**", DESCRIPTOR_NAME), recursive=True)):
            for tc in _parse(path, _signature(path)):
                # First root wins, so an override root earlier in the list can
                # shadow a mounted package of the same name.
                found.setdefault(tc.name, tc)
    return found


def installed():
    """`{name: Toolchain}` for every toolchain visible right now."""
    return discover()


def _clear_caches():
    _parse.cache_clear()
    _package_binds.cache_clear()


# Tests (and anything that rewrites a descriptor in place) clear the parse
# caches through the same name the old lru_cache exposed.
installed.cache_clear = _clear_caches


def get(name):
    """Resolve a toolchain name - e.g. a `project_settings.toolchain` value - to
    a Toolchain, or None if unset or unknown.

    This is the only place a name from the database becomes paths, and it is a
    dictionary lookup by design, never string interpolation, so a hostile value
    like `../../etc` cannot reach the filesystem.
    """
    if not name:
        return None
    return installed().get(name)


def names():
    """Sorted toolchain names, for the project-settings dropdown."""
    return sorted(installed())


# --------------------------------------------------------------- library closure

_LDD_ARROW = " => /"


def ldd_closure(path):
    """Absolute paths of every shared object `path` needs, including the ELF
    interpreter.

    The interpreter is listed *without* an `=>` - `/lib64/ld-linux-x86-64.so.2
    (0x...)`. Missing it produces a jail that has every library but cannot exec
    anything, which presents as a command yielding no output at all and nothing
    to explain why.
    """
    try:
        proc = subprocess.run(["ldd", path], stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return set()
    if proc.returncode != 0:
        return set()            # static binaries report "not a dynamic executable"

    libs = set()
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if _LDD_ARROW in line:
            libs.add(line.split(" => ")[1].split(" (")[0])
        elif stripped.startswith("/") and "(0x" in stripped:
            libs.add(stripped.split(" (")[0])
    return libs


@functools.lru_cache(maxsize=16)
def _package_binds(root, exe, python, binds, _tree_key):
    """The read-only bind list for a package.

    The closure covers every declared executable *and* every shared object
    inside the package - not just the executables. Measured on a real package:
    `ldd` on the bundled interpreter reports 6 libraries, but the true closure
    is 8, because extension modules pull `libcrypt` and `libgcc_s` and neither
    is visible on the interpreter itself. That is the same dlopen trap that once
    forced binding a whole system library directory into the conversion jail.
    """
    closure = set()
    for path in filter(None, (exe, python)):
        closure |= ldd_closure(path)
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if ".so" not in name:
                continue
            path = os.path.join(dirpath, name)
            if os.path.isfile(path) and not os.path.islink(path):
                closure |= ldd_closure(path)

    # Anything inside the package is already covered by binding the package.
    closure = {p for p in closure if not p.startswith(root + os.sep)}

    # Declared binds are *runtime* paths and are skipped when absent. A
    # descriptor cannot know the runtime image's layout: terminfo is
    # /lib/terminfo on Debian and /usr/share/terminfo elsewhere, so a package
    # declares both and gets whichever exists. Passing bwrap a bind source that
    # does not exist is a hard failure, so this filter is what makes declaring
    # alternatives safe.
    present = [b for b in binds if os.path.exists(b)]

    seen = {}
    for path in (root, *sorted(closure), *present):
        seen[path] = None
    return tuple(seen)
