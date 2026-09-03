#!/usr/bin/env python3
"""
Decode ESP32 core dumps with dynamically loaded ELF module symbols, locally.

This is the **standalone developer CLI**. The server no longer uses the
subprocess helpers below: crash decoding happens inside a bubblewrap sandbox in
the debug service, driven by a toolchain descriptor (see `gdb_app/` and
`toolchains.py`). What the two share is the registry line protocol, which lives
in `gdb_app/modreg.py` so there is exactly one implementation of it.

This CLI is still worth keeping. It runs on a developer host where IDF,
esp-coredump and the per-chip gdb launchers genuinely exist, it matches modules
by name rather than needing the database, and it is the reference to diff
against when a sandboxed report looks wrong.

The on-device module registry is read by resolving `s_mod_map` via gdb and
printing its fields with plain gdb `printf` commands - the Espressif toolchain
gdb has no Python scripting. Each record holds the module name, version, SHA1
and runtime section bases; module frames are then symbolicated by handing gdb
literal `add-symbol-file <elf> <text> -s .data <data> ...` commands.

Flow (host-driven, gdb invoked directly on a saved core ELF):

  1. esp-coredump converts the raw dump partition image into a core ELF
     (`--save-core`) and gives us the base panic/backtrace text.
  2. plain gdb reads `s_mod_map` from the core ELF -> [{name, version, sha1, sections}].
  3. each module's debug ELF is resolved (local CLI: by name).
  4. plain gdb re-runs with literal `add-symbol-file` per module and prints a
     module-symbolicated backtrace.

Local usage (modules matched by name):

  python decode_module_coredump.py dbg \
      --core crash.dmp \
      --prog build/pulse-ir-hub-esp32.elf \
      --module-elf ems-goodwe=ems-goodwe/build_bridge/ems-goodwe.app.elf
"""

import argparse
import glob
import os
import shutil
import subprocess
import sys
import tempfile

# The registry protocol lives in one place; these names are re-exported so the
# CLI's own interface (and its tests) are unchanged by the move.
from gdb_app.modreg import (  # noqa: F401
    MODSLOT_PREFIX,
    NSLOTS_PREFIX,
    SECTION_FIELDS,
    addsym_commands,
    parse_registry_output,
    render_add_symbols,
    write_addsym_gdbinit,
)
from gdb_app import modreg


def parse_elf_map_arg(spec: str) -> tuple[str, str]:
    """Parse 'name=path' into (name, path)."""
    if "=" not in spec:
        raise ValueError(f"--module-elf must be 'name=path' (got: {spec!r})")
    name, path = spec.split("=", 1)
    return name, path


def find_gdb(explicit: str | None = None) -> str:
    """Locate an xtensa gdb on this developer host. Any build works (we issue
    only plain commands, no Python). Order: explicit arg, $MODULE_GDB, PATH,
    common IDF tool dirs.

    Note this deliberately prefers the per-chip launcher (`xtensa-esp32-elf-gdb`)
    over the generic build: the launcher sets XTENSA_GNU_CONFIG, and without the
    right core configuration gdb produces a confidently wrong backtrace rather
    than an error. The sandboxed service sets that variable from the descriptor
    instead, since the launcher cannot run without /proc.
    """
    if explicit:
        return explicit
    env = os.environ.get("MODULE_GDB")
    if env:
        return env
    for name in ("xtensa-esp32-elf-gdb", "xtensa-esp-elf-gdb"):
        found = shutil.which(name)
        if found:
            return found
    roots = ("/opt/esp/tools", os.path.expanduser("~/.espressif/tools"))
    for root in roots:
        hits = glob.glob(os.path.join(root, "**", "xtensa-esp32-elf-gdb"), recursive=True)
        if hits:
            return sorted(hits)[-1]
    return "xtensa-esp32-elf-gdb"  # last resort; will fail loudly if absent


def save_core(
    dmp: str, prog: str, *, core_format: str = "raw", gdb: str | None = None
) -> tuple[str, str]:
    """Convert the raw dump into a core ELF via esp-coredump and capture the
    base (module-unaware) panic/backtrace text. Returns (core_elf_path, text).
    The caller owns the returned core ELF file and must unlink it."""
    fd, core_elf = tempfile.mkstemp(suffix=".elf", prefix="core_")
    os.close(fd)
    cmd = ["esp-coredump", "info_corefile", "-t", core_format, "-c", dmp,
           "--save-core", core_elf, "--gdb", find_gdb(gdb)]
    cmd.append(prog)
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        # esp-coredump not found / not executable: degrade to an empty core
        # (the caller still owns and cleans the temp file).
        return core_elf, f"# esp-coredump unavailable: {e}\n"
    return core_elf, (proc.stdout + proc.stderr).decode("utf-8", "replace")


def _gdb_batch(gdb: str, prog: str, core_elf: str, commands: list[str]) -> str:
    """Run gdb in batch on (prog, core_elf), executing `commands` in order after
    the core is loaded, and return combined stdout+stderr. Never raises."""
    args = [gdb, "-batch", "-nx", prog, "-ex", f"core-file {core_elf}"]
    for c in commands:
        args += ["-ex", c]
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError:
        return ""  # gdb not found / not executable: best-effort, no symbols
    return (proc.stdout + proc.stderr).decode("utf-8", "replace")


def read_registry(core_elf: str, prog: str, *, gdb: str | None = None,
                  runner=None) -> list[dict]:
    """Read `s_mod_map` from the core ELF using plain gdb commands.

    Thin wrapper over `gdb_app.modreg.read_registry`, supplying a runner that
    invokes gdb directly on this host. `runner` may be passed to override that -
    the sandboxed service supplies one that runs gdb inside a jail.
    """
    if runner is None:
        resolved = find_gdb(gdb)

        def runner(commands):
            return _gdb_batch(resolved, prog, core_elf, commands)

    return modreg.read_registry(runner)


def symbolicated_report(
    dmp: str, prog: str, loaded: list[dict], *,
    core_format: str = "raw", gdb: str | None = None,
) -> str:
    """Re-run esp-coredump with a literal add-symbol-file gdbinit so its full
    panic report (registers, every thread's stack, task table) has the module
    frames resolved inline. Returns the report text. Best-effort."""
    gi = write_addsym_gdbinit(loaded)
    try:
        cmd = ["esp-coredump", "info_corefile", "-t", core_format, "-c", dmp,
               "--gdb", find_gdb(gdb), "--extra-gdbinit-file", gi, prog]
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as e:
            return f"# esp-coredump unavailable: {e}\n"
        return (proc.stdout + proc.stderr).decode("utf-8", "replace")
    finally:
        try:
            os.remove(gi)
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Decode ESP32 core dumps with module symbols",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("operation", choices=["dbg", "info"],
                        help="'dbg' for interactive GDB, 'info' for a backtrace summary")
    parser.add_argument("--core", "-c", required=True, help="Path to core dump file")
    parser.add_argument("--core-format", "-t", choices=["auto", "b64", "elf", "raw"],
                        default="raw", dest="core_format",
                        help="Core dump format passed to esp-coredump (default: raw)")
    parser.add_argument("--prog", "-p", required=True, help="Path to host application ELF")
    parser.add_argument("--module-elf", action="append", default=[],
                        help="Module ELF mapping 'name=path' (repeatable). Matched by "
                             "module name against the on-device registry.")
    parser.add_argument("--gdb", help="Path to the xtensa GDB executable.")
    args = parser.parse_args()

    by_name: dict[str, str] = {}
    for spec in args.module_elf:
        name, path = parse_elf_map_arg(spec)
        by_name[name] = path

    core_elf, base = save_core(args.core, args.prog,
                               core_format=args.core_format, gdb=args.gdb)
    try:
        regs = read_registry(core_elf, args.prog, gdb=args.gdb)
        loaded = []
        for r in regs:
            elf = by_name.get(r["name"])
            ident = f"{r['name']} {r['version']} (sha1 {r['sha1'][:8]}...)"
            if elf:
                loaded.append({**r, "elf": elf})
                print(f"# module {ident}: symbols loaded", file=sys.stderr)
            else:
                print(f"# module {ident}: no --module-elf, skipping", file=sys.stderr)

        if args.operation == "dbg":
            # Interactive esp-coredump session with module symbols pre-loaded
            # (literal add-symbol-file via --extra-gdbinit-file).
            gi = write_addsym_gdbinit(loaded)
            try:
                cmd = ["esp-coredump", "dbg_corefile", "-t", args.core_format,
                       "-c", args.core, "--gdb", find_gdb(args.gdb)]
                if loaded:
                    cmd += ["--extra-gdbinit-file", gi]
                cmd.append(args.prog)
                subprocess.run(cmd)
            finally:
                try:
                    os.remove(gi)
                except OSError:
                    pass
        else:
            if loaded:
                print(symbolicated_report(args.core, args.prog, loaded,
                                          core_format=args.core_format, gdb=args.gdb))
            else:
                print(base)
    finally:
        try:
            os.remove(core_elf)
        except OSError:
            pass


if __name__ == "__main__":
    main()
