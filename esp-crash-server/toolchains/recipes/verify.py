#!/usr/bin/env python3
"""Validate a built toolchain package before anyone mounts it.

These are the guards that used to live in the Dockerfile's smoke test. They
moved here because the toolchain moved here: the image no longer downloads or
describes a toolchain, so the image can no longer be the thing that checks one.

Every check exists because its absence is *silent*. A wrong core configuration,
an environment variable pointing outside the sandbox, an incomplete library
closure - none of them raise. The debugger starts, reports the right
architecture, prints a backtrace, and the backtrace is wrong. That failure mode
cost a full debugging session once already; it is not allowed to recur.

One thing this deliberately does *not* do is decide the sandbox's bind list.
The library closure computed here is a build-host sanity check - that nothing is
unresolvable - and the paths are the build host's. They can differ completely
from the runtime image's: building on Arch yields `/usr/lib/libc.so.6` where the
Debian-based server image has `/lib/x86_64-linux-gnu/libc.so.6`. The
authoritative closure is therefore computed at load time, inside the container
that will actually run the jail.

Usage: verify.py <package-dir>
"""
import os
import shutil
import string
import subprocess
import sys

# The placeholder set is the interface between the service and a descriptor,
# so it is closed. An unrecognised one is a typo that would otherwise reach a
# command line as a literal and fail somewhere far away.
PLACEHOLDERS = {
    "root", "debugger", "python", "dump", "prog", "core", "symbols_file", "work",
}
# Only inside modules.add_symbols, where values come from the module registry.
MODULE_PLACEHOLDERS = {"elf", "name", "version", "sha1", "text", "data", "bss", "rodata"}

PHASES = ("core", "report")

failures = []
notes = []


def fail(msg):
    failures.append(msg)


def note(msg):
    notes.append(msg)


def load_yaml(path):
    """Parse the descriptor, re-execing into the package's own interpreter if
    the build host has no PyYAML. A package that bundles Python always has it
    (esptool depends on it), so this usually just works."""
    try:
        import yaml
    except ImportError:
        own = os.path.join(os.path.dirname(path), "python", "bin", "python3")
        if os.path.exists(own) and os.environ.get("_TC_VERIFY_REEXEC") != "1":
            os.environ["_TC_VERIFY_REEXEC"] = "1"
            os.execv(own, [own, os.path.abspath(__file__), os.path.dirname(path)])
        raise SystemExit(
            "error: PyYAML is required to verify a descriptor.\n"
            "  Install it on the build host (pip install PyYAML), or build a\n"
            "  package that bundles its own interpreter."
        )
    with open(path) as f:
        return yaml.safe_load(f)


def resolve(root, value):
    """Resolve a descriptor path, which is relative to the package unless
    absolute. Refuses to escape the package - defence in depth behind the
    read-only mount, not a substitute for it."""
    path = value if os.path.isabs(value) else os.path.join(root, value)
    real = os.path.realpath(path)
    if not os.path.isabs(value) and not real.startswith(os.path.realpath(root) + os.sep):
        fail(f"{value!r} escapes the package directory")
    return real


def check_placeholders(where, argv, allowed):
    for element in argv:
        if not isinstance(element, str):
            fail(f"{where}: every command element must be a string, got {element!r}")
            continue
        for _lit, field, _spec, _conv in string.Formatter().parse(element):
            if field is None:
                continue
            name = field.split(".")[0].split("[")[0]
            if name not in allowed:
                fail(f"{where}: unknown placeholder {{{field}}} "
                     f"(known: {', '.join(sorted(allowed))})")


def ldd_closure(exe):
    """Every shared object `exe` needs, and a hard failure on any that is
    unresolved - an incomplete closure is a debugger that dies inside the jail
    with 'error while loading shared libraries'."""
    proc = subprocess.run(["ldd", exe], capture_output=True, text=True)
    if proc.returncode != 0:
        # A static binary is fine and reports "not a dynamic executable".
        if "not a dynamic executable" in (proc.stdout + proc.stderr):
            return set()
        fail(f"ldd {exe} failed: {(proc.stdout + proc.stderr).strip()[:200]}")
        return set()
    libs = set()
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if "not found" in line:
            fail(f"{os.path.basename(exe)} needs {line.split()[0]}, which is not found")
        elif "=> /" in line:
            libs.add(line.split("=> ")[1].split(" (")[0])
        elif stripped.startswith("/") and "(0x" in stripped:
            # The ELF interpreter is listed bare, with no "=>" - e.g.
            # "/lib64/ld-linux-x86-64.so.2 (0x00007f...)". Miss it and the jail
            # has every library but nothing can exec at all, which presents as
            # a command producing no output whatsoever.
            libs.add(stripped.split(" (")[0])
    return libs


def main():
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    root = os.path.realpath(sys.argv[1])
    descriptor = os.path.join(root, "toolchain.yml")
    if not os.path.isfile(descriptor):
        raise SystemExit(f"error: no toolchain.yml in {root}")

    spec = load_yaml(descriptor)
    if not isinstance(spec, dict):
        raise SystemExit("error: toolchain.yml must be a mapping")

    for key in ("schema", "name", "arch", "version", "debugger"):
        if not spec.get(key):
            fail(f"missing required key: {key}")
    if spec.get("schema") != 1:
        fail(f"unsupported schema version: {spec.get('schema')!r}")

    # --- the debugger must exist and run
    debugger = None
    if spec.get("debugger"):
        debugger = resolve(root, spec["debugger"])
        if not (os.path.isfile(debugger) and os.access(debugger, os.X_OK)):
            fail(f"debugger {spec['debugger']!r} is not an executable file")
        else:
            proc = subprocess.run([debugger, "--version"], capture_output=True,
                                  text=True, timeout=120)
            if proc.returncode != 0:
                fail(f"debugger did not run: {(proc.stdout+proc.stderr).strip()[:200]}")
            else:
                note(f"debugger: {proc.stdout.splitlines()[0].strip()}")

    # --- the interpreter, if the package bundles one
    interpreter = None
    if spec.get("python"):
        interpreter = resolve(root, spec["python"])
        if not (os.path.isfile(interpreter) and os.access(interpreter, os.X_OK)):
            fail(f"python {spec['python']!r} is not an executable file")
        else:
            proc = subprocess.run([interpreter, "-c", "import sys;print(sys.version.split()[0])"],
                                  capture_output=True, text=True, timeout=120)
            if proc.returncode != 0:
                fail(f"bundled interpreter did not run: {(proc.stdout+proc.stderr).strip()[:200]}")
            else:
                note(f"python: {proc.stdout.strip()} (bundled)")

    # --- library closure over the executables AND every .so in the package.
    # `ldd` on the interpreter alone is not enough: extension modules pull
    # libraries it never mentions (libcrypt and libgcc_s, in practice), which is
    # the same dlopen trap that once forced binding /lib wholesale.
    outside = set()
    scanned = 0
    for exe in filter(None, (debugger, interpreter)):
        outside |= ldd_closure(exe)
        scanned += 1
    for dirpath, _dirs, files in os.walk(root):
        for name in files:
            if ".so" in name:
                path = os.path.join(dirpath, name)
                if os.path.isfile(path) and not os.path.islink(path):
                    outside |= ldd_closure(path)
                    scanned += 1
    outside = {p for p in outside if not p.startswith(root + os.sep)}
    note(f"library closure: {len(outside)} host libraries, from {scanned} objects")

    # --- environment: a path-valued variable must be inside the package or a
    # declared bind, or the sandbox silently falls back to a default
    binds = [os.path.realpath(b) for b in (spec.get("binds") or [])]
    for missing in (b for b in binds if not os.path.exists(b)):
        fail(f"declared bind does not exist: {missing}")

    def env_paths_ok(env, where):
        for key, value in (env or {}).items():
            if not isinstance(value, str) or "{root}" not in value and not value.startswith("/"):
                continue
            expanded = value.replace("{root}", root)
            if not os.path.exists(expanded.rstrip("/")):
                fail(f"{where}: {key}={value} does not exist in the package")
            elif not (os.path.realpath(expanded.rstrip("/")).startswith(root + os.sep)
                      or any(os.path.realpath(expanded.rstrip("/")).startswith(b) for b in binds)):
                fail(f"{where}: {key}={value} is neither inside the package nor a declared bind, "
                     f"so it would not exist inside the sandbox")

    env_paths_ok(spec.get("env"), "env")

    # --- phases and their placeholders
    allowed = set(PLACEHOLDERS)
    if not spec.get("python"):
        allowed.discard("python")
    for phase in PHASES:
        section = spec.get(phase)
        if section is None:
            note(f"{phase}: not declared")
            continue
        commands = section.get("commands")
        if not commands:
            fail(f"{phase}: declared but has no commands")
            continue
        for i, argv in enumerate(commands):
            if not isinstance(argv, list):
                fail(f"{phase}.commands[{i}] must be a list of strings, not a shell string")
                continue
            check_placeholders(f"{phase}.commands[{i}]", argv, allowed)
        check_placeholders(f"{phase}.with_symbols", section.get("with_symbols") or [], allowed)

    interactive = spec.get("interactive") or {}
    if not interactive.get("command"):
        fail("interactive.command is required - it is what the pty attaches to")
    else:
        check_placeholders("interactive.command", interactive["command"], allowed)
        check_placeholders("interactive.with_symbols",
                           interactive.get("with_symbols") or [], allowed)

    modules = spec.get("modules")
    if modules is None:
        note("modules: not declared (no runtime module resolution)")
    else:
        if not modules.get("registry"):
            fail("modules.registry is required when modules: is declared")
        check_placeholders("modules.batch", modules.get("batch") or [], allowed)
        for line in modules.get("add_symbols") or []:
            check_placeholders("modules.add_symbols", [line],
                               allowed | MODULE_PLACEHOLDERS)

    # --- variants
    variants = spec.get("variants") or {}
    for vid, variant in variants.items():
        env_paths_ok((variant or {}).get("env"), f"variants.{vid}.env")
    note(f"toolchain ids: {', '.join(sorted(variants)) or spec.get('name', '?')}")

    for line in notes:
        print(f"  {line}")
    if failures:
        print()
        for line in failures:
            print(f"  FAIL: {line}", file=sys.stderr)
        raise SystemExit(f"{len(failures)} problem(s) in {descriptor}")
    print(f"  OK      {descriptor}")


if __name__ == "__main__":
    main()
