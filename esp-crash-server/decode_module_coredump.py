#!/usr/bin/env python3
"""
Decode ESP32 core dumps with dynamically loaded ELF module symbols.

The on-device module registry is read from the coredump by resolving the
`s_mod_map` symbol via gdb and printing its fields with plain gdb `printf`
commands (no gdb-Python: the Espressif toolchain gdb is built without Python
scripting). Each record holds the module name, version, its SHA1, and the
runtime section bases. Module frames are
then symbolicated by handing gdb literal
`add-symbol-file <elf> <text> -s .data <data> ...` commands whose addresses are
the runtime section bases read straight out of the registry.

Flow (host-driven, gdb invoked directly on a saved core ELF):

  1. esp-coredump converts the raw dump partition image into a core ELF
     (`--save-core`) and gives us the base panic/backtrace text.
  2. plain gdb reads `s_mod_map` from the core ELF -> [{name, version, sha1, sections}].
  3. each module's debug ELF is resolved (server: by sha1; local CLI: by name).
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
import re
import shutil
import subprocess
import sys
import tempfile

# Section names whose runtime base addresses the registry records and gdb's
# add-symbol-file needs. `text` is the positional base; the rest are `-s`.
SECTION_FIELDS = ("text", "data", "bss", "rodata")

# Delimited line emitted by the gdb registry-read script, one per slot:
#   MODSLOT|<i>|<name>|<version>|<sha1-hex>|<text>|<data>|<bss>|<rodata>
MODSLOT_PREFIX = "MODSLOT|"
NSLOTS_PREFIX = "NSLOTS="


def parse_elf_map_arg(spec: str) -> tuple[str, str]:
    """Parse 'name=path' into (name, path)."""
    if "=" not in spec:
        raise ValueError(f"--module-elf must be 'name=path' (got: {spec!r})")
    name, path = spec.split("=", 1)
    return name, path


def find_gdb(explicit: str | None = None) -> str:
    """Locate an xtensa gdb. Any build works (we issue only plain commands, no
    Python). Order: explicit arg, $MODULE_GDB, PATH, common IDF tool dirs."""
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


def _slot_printf(i: int) -> str:
    """gdb `printf` command that emits one delimited MODSLOT line for slot i:
    the module name and version, the 20-byte sha1 as hex, and the four section
    base addresses."""
    sha = "".join("%02x" for _ in range(20))
    sha_args = ", ".join(f"s_mod_map[{i}].sha1[{b}]" for b in range(20))
    addr_args = ", ".join(f"s_mod_map[{i}].{s}.addr" for s in SECTION_FIELDS)
    fmt = f"{MODSLOT_PREFIX}{i}|%s|%s|{sha}|%u|%u|%u|%u\\n"
    return (f'printf "{fmt}", s_mod_map[{i}].name, '
            f's_mod_map[{i}].version, {sha_args}, {addr_args}')


def parse_registry_output(text: str) -> list[dict]:
    """Parse MODSLOT lines into occupied-slot records. Best-effort: a slot is
    occupied iff name is non-empty and text.addr != 0. Returns
    [{name, version, sha1, text, data, bss, rodata}] with addresses as ints."""
    mods = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith(MODSLOT_PREFIX):
            continue
        parts = line.split("|")
        # MODSLOT | idx | name | version | sha1 | text | data | bss | rodata
        if len(parts) != 9:
            continue
        _, _idx, name, version, sha1, t, d, b, r = parts
        try:
            text_addr, data_addr, bss_addr, rodata_addr = (
                int(t) & 0xffffffff, int(d) & 0xffffffff,
                int(b) & 0xffffffff, int(r) & 0xffffffff,
            )
        except ValueError:
            continue
        if not name or text_addr == 0:
            continue  # free or mid-load slot
        mods.append({
            "name": name, "version": version, "sha1": sha1,
            "text": text_addr, "data": data_addr,
            "bss": bss_addr, "rodata": rodata_addr,
        })
    return mods


def read_registry(core_elf: str, prog: str, *, gdb: str | None = None) -> list[dict]:
    """Read `s_mod_map` from the core ELF using plain gdb commands. Returns
    occupied-slot records (possibly empty). Never raises on a missing symbol."""
    gdb = find_gdb(gdb)
    # Pass A: how many slots? (sizeof from DWARF; works without the core loaded
    # but we load it anyway for a single, simple invocation path.)
    out = _gdb_batch(gdb, prog, core_elf,
                     [f'printf "{NSLOTS_PREFIX}%d\\n", '
                      f'(int)(sizeof(s_mod_map)/sizeof(s_mod_map[0]))'])
    n = 0
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(NSLOTS_PREFIX):
            try:
                n = int(line[len(NSLOTS_PREFIX):])
            except ValueError:
                n = 0
            break
    if n <= 0:
        return []  # no s_mod_map symbol, or unreadable
    # Pass B: dump each slot.
    out = _gdb_batch(gdb, prog, core_elf, [_slot_printf(i) for i in range(n)])
    return parse_registry_output(out)


def addsym_commands(loaded: list[dict]) -> list[str]:
    """Build literal `add-symbol-file` gdb commands for resolved modules.
    `loaded` items are registry records (text/data/bss/rodata ints) plus an
    'elf' path. Addresses are emitted as hex so any gdb can place the sections
    without evaluating the registry."""
    cmds = []
    for m in loaded:
        cmds.append(
            "add-symbol-file {elf} {text:#x} "
            "-s .data {data:#x} -s .bss {bss:#x} -s .rodata {rodata:#x}".format(**m)
        )
    return cmds


def write_addsym_gdbinit(loaded: list[dict]) -> str:
    """Write literal add-symbol-file commands for `loaded` to a temp gdbinit and
    return its path. esp-coredump sources it via --extra-gdbinit-file so its own
    panic report resolves module frames inline. The caller must delete the file."""
    fd, path = tempfile.mkstemp(suffix=".gdbinit", prefix="modsym_")
    with os.fdopen(fd, "w") as f:
        cmds = addsym_commands(loaded)
        f.write("\n".join(cmds))
        if cmds:
            f.write("\n")
    return path


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
