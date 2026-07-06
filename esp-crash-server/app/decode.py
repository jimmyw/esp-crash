"""Coredump module-symbol resolution. Mechanical move of server.py's
_resolve_modules_for_dump, unchanged. Shared by the crashes and cron
blueprints - kept in its own module (rather than duplicated, or imported via
`from app.decode import _resolve_modules_for_dump` in each blueprint) so a
single patch target (`app.decode._resolve_modules_for_dump`) works for
mocking it from tests regardless of which blueprint calls it."""
import os
import bz2
import tempfile

import decode_module_coredump as mod_decoder


def _resolve_modules_for_dump(db, dump_path, prog_path):
    """
    Read the on-device module registry from the coredump (plain gdb, no Python:
    the toolchain gdb has no scripting) and resolve each module's debug ELF from
    module_elf by app_sha1.

    Returns (regs, loaded, base_text, core_elf, status_lines):
      regs:    list[{name, sha1, text, data, bss, rodata}] from the registry.
      loaded:  subset of regs (same dicts) with an extra 'elf' temp-file path,
               for modules whose symbols were found in module_elf.
      base_text: esp-coredump's module-unaware panic/backtrace text.
      core_elf:  path to the saved core ELF (used to symbolicate; owned by caller).
      status_lines: human-readable annotations ("symbols loaded"/"not available").
    The caller owns `core_elf` and every loaded['elf'] temp file and must unlink
    them.
    """
    core_elf, base_text = mod_decoder.save_core(dump_path, prog_path)
    loaded = []
    status = []
    try:
        regs = mod_decoder.read_registry(core_elf, prog_path)
        for entry in regs:
            sha1 = entry.get("sha1", "")
            rows = db.get_data(
                "SELECT elf_file FROM module_elf WHERE app_sha1 = %s LIMIT 1", (sha1,)
            )
            if not rows:
                status.append(
                    f"# module {entry['name']} (sha1 {sha1[:8]}...): symbols not available"
                )
                continue
            try:
                blob = bz2.decompress(rows[0]["elf_file"])
            except IOError:
                blob = rows[0]["elf_file"]
            with tempfile.NamedTemporaryFile(suffix=".elf", delete=False, prefix="mod_") as ef:
                ef.write(blob)
            loaded.append({**entry, "elf": ef.name})
            status.append(f"# module {entry['name']} (sha1 {sha1[:8]}...): symbols loaded")
    except Exception:
        for m in loaded:
            try:
                os.remove(m["elf"])
            except OSError:
                pass
        try:
            os.remove(core_elf)
        except OSError:
            pass
        raise
    return regs, loaded, base_text, core_elf, status
