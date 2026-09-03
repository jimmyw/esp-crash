#!/usr/bin/env python3
"""Generate a toolchain's jail manifest at image build time.

Resolves the shared-library closure of a debugger binary with `ldd` and records
it, together with any auxiliary data paths and environment, as
`jail-manifest.json`. `app/toolchains.py` reads these at runtime to assemble the
read-only bind list for a bubblewrap jail.

The point of doing this at build time is failure timing: if a base-image update
changes the closure, the build breaks here (or in the accompanying smoke test)
rather than a user's debug session breaking later. Nothing in this script is
architecture- or vendor-specific - it takes a path to any gdb.

Usage:
  make_jail_manifest.py --name xtensa-esp-elf --arch xtensa --version 16.3 \
      --exe /opt/.../xtensa-esp-elf-gdb-no-python \
      --converter esp_coredump \
      --extra /opt/esp/tools/esp-rom-elfs/20241011 \
      --env ESP_ROM_ELF_DIR=/opt/esp/tools/esp-rom-elfs/20241011
"""
import argparse
import json
import os
import re
import subprocess
import sys

# `ldd` lines we care about:
#   \tlibfoo.so.1 => /lib/x86_64-linux-gnu/libfoo.so.1 (0x00007f...)
#   \t/lib64/ld-linux-x86-64.so.2 (0x00007f...)          <- the interpreter
# and ones we must reject:
#   \tlibbar.so => not found
_ARROW = re.compile(r"^\s*\S+\s+=>\s+(/\S+)")
_BARE = re.compile(r"^\s*(/\S+)\s+\(0x")
_NOTFOUND = re.compile(r"^\s*(\S+)\s+=>\s+not found")


def ldd_closure(exe):
    """Absolute paths of every shared object `exe` needs, including the ELF
    interpreter. Raises if any dependency is unresolved - a manifest that
    silently omitted one would produce a jail where gdb dies with 'error while
    loading shared libraries', which is exactly the failure mode this build
    step exists to prevent."""
    proc = subprocess.run(["ldd", exe], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise SystemExit(f"ldd {exe} failed (exit {proc.returncode}):\n{proc.stdout}")

    libs, missing = [], []
    for line in proc.stdout.splitlines():
        if (m := _NOTFOUND.match(line)):
            missing.append(m.group(1))
            continue
        if (m := _ARROW.match(line)) or (m := _BARE.match(line)):
            libs.append(m.group(1))
        # linux-vdso.so.1 has no backing file (kernel-provided) - nothing to bind.
    if missing:
        raise SystemExit(f"ldd {exe}: unresolved dependencies: {', '.join(missing)}")
    if not libs:
        raise SystemExit(f"ldd {exe}: no libraries resolved - is it a static binary or a wrapper?")

    # Follow symlinks *and* keep the original name: ld.so opens the path in
    # DT_NEEDED, so both the link and its target must exist in the jail.
    out = {}
    for p in libs:
        out[p] = None
        real = os.path.realpath(p)
        if real != p:
            out[real] = None
    return sorted(out)


_LIBPYTHON = re.compile(r"libpython(\d+\.\d+)")


def gdb_data_dir(exe):
    """gdb's own data directory, asked of gdb rather than guessed.

    gdb loads pretty-printers, the syscall database and its Python support
    files from here. Missing, it still runs but degrades quietly, so the jail
    should have it.
    """
    proc = subprocess.run([exe, "-batch", "-nx", "-ex", "show data-directory"],
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, timeout=60)
    m = re.search(r'data directory is "([^"]+)"', proc.stdout or "")
    if m and os.path.isdir(m.group(1)):
        return os.path.realpath(m.group(1))
    return None


def locale_paths():
    """glibc's locale data, if this system keeps it in files.

    Without it `setlocale` inside the jail falls back to the C locale and gdb
    reports the codeset as ANSI_X3.4-1968, then warns "could not convert ...
    to UTF-32 ... please file a bug report" every time it prints a char array.
    Harmless but alarming, and it reaches the user's terminal. Espressif's gdb
    does not hit this; a distribution gdb (the likely choice for ARM and
    RISC-V targets) does.
    """
    return [p for p in ("/usr/lib/locale",) if os.path.isdir(p)]


def python_home(libs):
    """The Python stdlib directory a Python-enabled gdb will need, if any.

    Many distribution gdbs (including `gdb-multiarch`, the obvious choice for
    ARM and RISC-V targets) link libpython. Such a gdb cannot initialise inside
    a jail that has the library but not the stdlib - it prints a "Python path
    configuration" dump and exits before running a single command. Since `ldd`
    reveals the library but not the interpreter's data files, the connection
    has to be made here.

    Espressif's toolchain ships an explicit `-no-python` gdb, which is the
    better choice for a sandbox when it exists: fewer files, no interpreter.
    """
    for lib in libs:
        if (m := _LIBPYTHON.search(os.path.basename(lib))):
            version = m.group(1)
            for root in ("/usr/lib", "/usr/local/lib", "/usr/share"):
                cand = os.path.join(root, f"python{version}")
                if os.path.isdir(cand):
                    return os.path.realpath(cand)
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name", required=True, help="toolchain id, as stored in project_settings.toolchain")
    ap.add_argument("--arch", required=True, help="target architecture (xtensa, riscv32, arm, ...)")
    ap.add_argument("--version", required=True)
    ap.add_argument("--exe", required=True, help="the gdb binary the jail should run")
    ap.add_argument("--converter", required=True,
                    help="name of the gdb_app.converters plugin for this target's crash artifacts")
    ap.add_argument("--extra", action="append", default=[],
                    help="additional path to bind read-only (data files, ROM ELFs); repeatable")
    ap.add_argument("--env", action="append", default=[], metavar="K=V",
                    help="environment the jail should set; repeatable")
    ap.add_argument("--out", help="manifest path (default: jail-manifest.json beside --exe)")
    args = ap.parse_args()

    exe = os.path.realpath(args.exe)
    if not os.path.isfile(exe) or not os.access(exe, os.X_OK):
        raise SystemExit(f"--exe {args.exe!r} is not an executable file "
                         f"(note: some toolchains ship a small per-chip wrapper "
                         f"under the obvious name and the real gdb under another)")

    env = {}
    for item in args.env:
        if "=" not in item:
            raise SystemExit(f"--env expects K=V, got {item!r}")
        k, v = item.split("=", 1)
        env[k] = v

    for p in args.extra:
        if not os.path.exists(p):
            raise SystemExit(f"--extra {p!r} does not exist")

    libs = ldd_closure(exe)
    extra = [os.path.realpath(p) for p in args.extra]

    # Auto-discovered paths this debugger needs but ldd cannot reveal. Added
    # here rather than left to each Dockerfile invocation so a new toolchain
    # cannot quietly omit them - the symptom is a debugger that works when run
    # normally and dies only inside the jail.
    if (data_dir := gdb_data_dir(exe)) and data_dir not in extra:
        extra.append(data_dir)
    for path in locale_paths():
        if path not in extra:
            extra.append(path)
    if (home := python_home(libs)):
        if home not in extra:
            extra.append(home)
        env.setdefault("PYTHONHOME", "/usr")
        print(f"note: {os.path.basename(exe)} links libpython; adding {home}. "
              f"A no-python build of gdb makes for a smaller sandbox if the "
              f"toolchain ships one.", file=sys.stderr)

    manifest = {
        "name": args.name,
        "arch": args.arch,
        "version": args.version,
        "exe": exe,
        "converter": args.converter,
        "libs": libs,
        "extra": sorted(extra),
        "env": env,
    }

    out = args.out or os.path.join(os.path.dirname(exe), "jail-manifest.json")
    # A toolchain installed outside its own directory tree (a system gdb, say)
    # gets its manifest written wherever --out points, so create that.
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {out}: {len(manifest['libs'])} libs, "
          f"{len(manifest['extra'])} extra path(s)", file=sys.stderr)


if __name__ == "__main__":
    main()
