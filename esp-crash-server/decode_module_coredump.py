#!/usr/bin/env python3
"""
Decode ESP32 core dumps with dynamically loaded ELF module symbols.

The on-device module map embedded in .dram2.coredump is read straight from
the dump. Just supply each loaded module's ELF, mapped by name.

  python decode_module_coredump.py dbg \
      --core crash.dmp \
      --prog build/pulse-ir-hub-esp32.elf \
      --module-elf ems-goodwe=ems-goodwe/build_bridge/ems-goodwe.app.elf

On-device map format (little-endian, 4-byte aligned):
  registry { u32 magic=0x4D4F444D ('MODM'); u8 capacity; pad[3];
             entry modules[capacity]; }   # capacity = CONFIG_MOD_LOADER_MAX_MODULES
  entry    { char name[64]; u8 sha1[20]; section text; section data;
             section bss; section rodata; }
  section  { u32 addr; u32 v_addr; u32 size; }

The array is sparse: a slot is occupied iff name[0] != 0 and its .text addr is
non-zero. Released slots are zeroed; mid-load slots have a name but a zero .text.
"""

import argparse
import io
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from elftools.elf.elffile import ELFFile

MOD_MAP_MAGIC = 0x4D4F444D  # 'MODM' as LE u32
MOD_MAP_NAME_LEN = 64
MOD_MAP_SHA1_LEN = 20
SECTION_SIZE = 12
ENTRY_SIZE = MOD_MAP_NAME_LEN + MOD_MAP_SHA1_LEN + 4 * SECTION_SIZE  # 64 + 20 + 48 = 132
REGISTRY_HEADER_SIZE = 8  # u32 magic + u8 capacity + 3 pad bytes

# The on-device array size is a build-time Kconfig (CONFIG_MOD_LOADER_MAX_MODULES,
# range 1..32). The registry header records the actual capacity so we never need
# to guess; this is only the upper bound we trust for a candidate header.
MOD_MAP_CAPACITY_LIMIT = 32

# Mirror of the C-side _Static_assert in mod_loader_registry.c — keep these in sync.
assert ENTRY_SIZE == 132, "ENTRY_SIZE drifted from mod_record (must be 132)"
ELF_MAGIC = b"\x7fELF"


def _is_plausible_addr(addr: int) -> bool:
    """
    Coarse sanity filter for ESP32 runtime addresses. Module sections live in
    the IRAM/IROM bus window (.text/.rodata via flash mmap) or in DRAM
    (.data/.bss on heap). Anything outside these ranges means we hit a stray
    'MODM' byte sequence somewhere else in the dump.
    """
    if addr == 0:
        return True  # unused slots are zero
    return 0x3F000000 <= addr < 0x60000000


def _decode_entry(blob: bytes, offset: int) -> dict | None:
    raw_name = blob[offset : offset + MOD_MAP_NAME_LEN]
    name = raw_name.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
    if not name or any(ord(c) < 0x20 or ord(c) > 0x7E for c in name):
        return None

    sha1_bytes = blob[
        offset + MOD_MAP_NAME_LEN : offset + MOD_MAP_NAME_LEN + MOD_MAP_SHA1_LEN
    ]
    sha1_hex = sha1_bytes.hex()

    sec_base = offset + MOD_MAP_NAME_LEN + MOD_MAP_SHA1_LEN
    out = {"name": name, "sha1": sha1_hex}
    for i, sec_name in enumerate(("text", "data", "bss", "rodata")):
        addr, v_addr, size = struct.unpack_from(
            "<III", blob, sec_base + i * SECTION_SIZE
        )
        # A committed module's .text always maps into the IRAM/IROM window and
        # is never 0; .text == 0 means the slot was acquired but not yet
        # committed (mid-load) or was released, so skip it.
        if sec_name == "text" and addr == 0:
            return None
        if not _is_plausible_addr(addr):
            return None
        out[f"{sec_name}_addr"] = f"0x{addr:08x}"
        out[f"{sec_name}_vaddr"] = f"0x{v_addr:08x}"
        out[f"{sec_name}_size"] = size
    return out


def _decode_registry(blob: bytes, offset: int) -> list[dict] | None:
    """
    Try to decode a registry header at `offset`. Returns the list of decoded
    occupied entries (possibly empty), or None if the candidate fails
    validation. The header self-describes its slot capacity; the array is
    sparse, so empty/uncommitted/corrupt slots are skipped individually rather
    than failing the whole registry.
    """
    if offset + REGISTRY_HEADER_SIZE > len(blob):
        return None
    capacity = blob[offset + 4]
    if capacity < 1 or capacity > MOD_MAP_CAPACITY_LIMIT:
        return None
    if offset + REGISTRY_HEADER_SIZE + capacity * ENTRY_SIZE > len(blob):
        return None
    entries: list[dict] = []
    for i in range(capacity):
        entry_offset = offset + REGISTRY_HEADER_SIZE + i * ENTRY_SIZE
        decoded = _decode_entry(blob, entry_offset)
        if decoded is not None:
            entries.append(decoded)
    return entries


def parse_module_map_from_coredump(core_path: str, verbose: bool = False) -> list[dict]:
    """
    Read the on-device module map out of an ELF-format core dump.

    The coredump is always an ELF (CONFIG_ESP_COREDUMP_DATA_FORMAT_ELF=y is
    the default). The .dram2.coredump section is captured as part of a
    PT_LOAD program header; we search the MODM magic only inside those
    segments to avoid false positives in ELF metadata or other regions.

    When the file was read raw from flash, a small chip-side header may
    precede the ELF; we skip past it by locating the first ELF magic.
    """
    raw = Path(core_path).read_bytes()
    elf_offset = raw.find(ELF_MAGIC)
    if elf_offset < 0:
        raise ValueError(
            f"{core_path}: no ELF header found (is this an ESP-IDF coredump?)"
        )

    if verbose:
        print(
            f"DEBUG: coredump bytes={len(raw)} elf_offset=0x{elf_offset:x}",
            file=sys.stderr,
        )

    elf_bytes = raw[elf_offset:]
    needle = struct.pack("<I", MOD_MAP_MAGIC)
    modules: list[dict] = []
    seen_segments = 0
    load_segments = 0
    candidate_hits = 0
    decoded_entries = 0

    with ELFFile(io.BytesIO(elf_bytes)) as elf:
        for segment in elf.iter_segments():
            if segment.header.p_type != "PT_LOAD":
                continue
            load_segments += 1
            data = segment.data()
            pos = 0
            while True:
                pos = data.find(needle, pos)
                if pos < 0:
                    break
                candidate_hits += 1
                entries = _decode_registry(data, pos)
                if entries is None:
                    pos += 1
                    continue
                modules.extend(entries)
                decoded_entries += len(entries)
                seen_segments += 1
                capacity = data[pos + 4]
                pos += REGISTRY_HEADER_SIZE + capacity * ENTRY_SIZE

    if verbose:
        print(
            "DEBUG: "
            f"pt_load_segments={load_segments} "
            f"modm_hits={candidate_hits} "
            f"valid_registries={seen_segments} "
            f"decoded_entries={decoded_entries}",
            file=sys.stderr,
        )

    if seen_segments > 1:
        print(
            f"NOTE: found {seen_segments} module-map candidates in coredump; "
            "merged all entries.",
            file=sys.stderr,
        )
    return modules


def parse_elf_map_arg(spec: str) -> tuple[str, str]:
    """Parse 'name=path' into (name, path)."""
    if "=" not in spec:
        raise ValueError(f"--module-elf must be 'name=path' (got: {spec!r})")
    name, path = spec.split("=", 1)
    return name, path


def generate_gdbinit(modules: list[dict], output_path: str):
    """Generate a GDB init file with add-symbol-file commands."""
    with open(output_path, "w") as f:
        f.write("# Auto-generated by decode_module_coredump.py\n")
        f.write("# Module symbol loading commands\n\n")
        for mod in modules:
            elf = mod["elf"]
            # Path written into the add-symbol-file line. Defaults to the path
            # we read below; callers (e.g. the download packager) can set
            # 'elf_display' to a relative path that is valid where gdb runs.
            elf_display = mod.get("elf_display", elf)
            # Parse addresses (may be int or hex string)
            text_runtime = int(mod["text_addr"], 16) if isinstance(mod["text_addr"], str) and mod["text_addr"].startswith("0x") else int(mod["text_addr"])
            data = int(mod["data_addr"], 16) if isinstance(mod["data_addr"], str) and mod["data_addr"].startswith("0x") else int(mod["data_addr"])
            bss = int(mod["bss_addr"], 16) if isinstance(mod["bss_addr"], str) and mod["bss_addr"].startswith("0x") else int(mod["bss_addr"])
            rodata = int(mod["rodata_addr"], 16) if isinstance(mod["rodata_addr"], str) and mod["rodata_addr"].startswith("0x") else int(mod["rodata_addr"])

            # `add-symbol-file FILE <addr>` expects <addr> to be the *runtime*
            # address of the .text section; GDB computes the per-section slide
            # itself as (addr - the ELF's .text sh_addr). text_runtime already IS
            # that runtime address, so pass it as-is. Do NOT pre-subtract the
            # ELF's .text vaddr: when sh_addr != 0 (ESP ELF modules link .text at
            # a small non-zero vaddr) that double-counts the vaddr and shifts
            # every symbol, mislabeling frames to the next function up.
            f.write(f"echo \\n=== Loading module '{mod['name']}' symbols ===\\n\n")
            f.write(
                f"add-symbol-file {elf_display} {hex(text_runtime)} "
                f"-s .data {hex(data)} "
                f"-s .bss {hex(bss)} "
                f"-s .rodata {hex(rodata)}\n"
            )
        f.write("\necho \\n=== Module symbols loaded. Use 'bt' or 'info threads' ===\\n\n")


def run_espcoredump(args, modules: list[dict], operation: str):
    """Symbolicate a coredump, loading any module symbols via gdbinit.

    The whole job is: generate a gdbinit with add-symbol-file lines for the
    modules, then hand it to the esp-coredump console script through its native
    --extra-gdbinit-file (honored by esp_coredump's CLI; see coredump.py). The
    stored coredump is a raw partition image, so -t raw parses it directly — no
    normalization needed.
    """
    gdbinit_path = None
    try:
        cmd = ["esp-coredump", operation, "-t", args.core_format, "-c", args.core]
        if modules:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".gdbinit", delete=False, prefix="mod_"
            ) as f:
                gdbinit_path = f.name
            generate_gdbinit(modules, gdbinit_path)
            cmd += ["--extra-gdbinit-file", gdbinit_path]
            print(f"Generated GDB init: {gdbinit_path}", file=sys.stderr)
        if args.gdb:
            cmd += ["--gdb", args.gdb]
        cmd.append(args.prog)
        print(f"Running: {' '.join(cmd)}", file=sys.stderr)
        subprocess.run(cmd)
    finally:
        # Keep the gdbinit for interactive sessions so the user can re-source it;
        # otherwise clean it up.
        if gdbinit_path:
            if operation == "dbg_corefile":
                print(f"\nGDB init file preserved at: {gdbinit_path}", file=sys.stderr)
            else:
                os.unlink(gdbinit_path)


def main():
    parser = argparse.ArgumentParser(
        description="Decode ESP32 core dumps with module symbols",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "operation",
        choices=["dbg", "info"],
        help="'dbg' for interactive GDB, 'info' for backtrace summary",
    )
    parser.add_argument(
        "--core", "-c", required=True, help="Path to core dump file (raw binary)"
    )
    parser.add_argument(
        "--core-format",
        "-t",
        choices=["auto", "b64", "elf", "raw"],
        default="raw",
        dest="core_format",
        help="Core dump format passed to esp-coredump (default: raw)",
    )
    parser.add_argument(
        "--prog", "-p", required=True, help="Path to host application ELF"
    )
    parser.add_argument(
        "--module-elf",
        action="append",
        default=[],
        help=(
            "Module ELF mapping 'name=path' (repeatable). Used to resolve "
            "names found in the on-device module map embedded in the coredump."
        ),
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Print extraction diagnostics (ELF offset, PT_LOAD scans, MODM hits).",
    )
    parser.add_argument(
        "--gdb",
        help="Path to GDB executable passed to espcoredump.py (for example /opt/homebrew/bin/gdb).",
    )

    args = parser.parse_args()

    elf_map: dict[str, str] = {}
    for spec in args.module_elf:
        name, path = parse_elf_map_arg(spec)
        elf_map[name] = path

    modules: list[dict] = []
    for m in parse_module_map_from_coredump(args.core, args.verbose):
        elf = elf_map.get(m["name"])
        if not elf:
            print(
                f"WARNING: coredump map references module '{m['name']}' but no "
                f"--module-elf {m['name']}=<path> was supplied; skipping.",
                file=sys.stderr,
            )
            continue
        m["elf"] = elf
        modules.append(m)
        print(
            f"Extracted module '{m['name']}' (sha1={m['sha1']}) from coredump map: "
            f"text={m['text_addr']} data={m['data_addr']} "
            f"bss={m['bss_addr']} rodata={m['rodata_addr']}",
            file=sys.stderr,
        )

    if not modules:
        print(
            "WARNING: No modules resolved. Running without module symbols.",
            file=sys.stderr,
        )

    operation = "dbg_corefile" if args.operation == "dbg" else "info_corefile"
    run_espcoredump(args, modules, operation)


if __name__ == "__main__":
    main()
