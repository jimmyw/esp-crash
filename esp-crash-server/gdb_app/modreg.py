"""The on-device module registry protocol.

Firmware built with this repo's C component keeps a table of runtime-loaded
modules in `s_mod_map`: for each slot, a name, a version, the SHA1 of the
shipped binary, and the runtime base address of each section. Reading it back
out of a core dump is what lets module frames be symbolicated.

The debugger has no scripting available (Espressif's gdb is built without
Python), so the table is read by issuing plain `printf` commands and parsing
delimited lines back. That line protocol is the fiddly part of this codebase and
it lives here, in exactly one place: the debug service drives it inside a jail,
and `decode_module_coredump.py` drives it directly for local use.

Nothing here is Espressif-specific despite the neighbourhood - `s_mod_map` is a
convention of *our* C component, and a target that does not use it simply has no
symbol for the registry to find, which `read_registry` reports as an empty list.
"""
import os
import string
import tempfile

# Section names whose runtime base addresses the registry records and the
# debugger needs in order to place a module's symbols.
SECTION_FIELDS = ("text", "data", "bss", "rodata")

# Delimited line emitted per slot:
#   MODSLOT|<i>|<name>|<version>|<sha1-hex>|<text>|<data>|<bss>|<rodata>
MODSLOT_PREFIX = "MODSLOT|"
NSLOTS_PREFIX = "NSLOTS="

# gdb's syntax for placing a module's symbols. The descriptor supplies this per
# toolchain (lldb would say `target modules add`); this is the default the
# local CLI uses and the reference for what a descriptor should contain.
DEFAULT_ADD_SYMBOLS = (
    "add-symbol-file {elf} {text:#x} -s .data {data:#x} "
    "-s .bss {bss:#x} -s .rodata {rodata:#x}",
)


def slot_printf(i):
    """The `printf` command that emits one delimited line for slot `i`: name,
    version, the 20-byte SHA1 as hex, and the four section base addresses."""
    sha = "".join("%02x" for _ in range(20))
    sha_args = ", ".join(f"s_mod_map[{i}].sha1[{b}]" for b in range(20))
    addr_args = ", ".join(f"s_mod_map[{i}].{s}.addr" for s in SECTION_FIELDS)
    fmt = f"{MODSLOT_PREFIX}{i}|%s|%s|{sha}|%u|%u|%u|%u\\n"
    return (f'printf "{fmt}", s_mod_map[{i}].name, '
            f's_mod_map[{i}].version, {sha_args}, {addr_args}')


def nslots_printf():
    """The command that reports how many slots the table has, read from DWARF."""
    return (f'printf "{NSLOTS_PREFIX}%d\\n", '
            f'(int)(sizeof(s_mod_map)/sizeof(s_mod_map[0]))')


def parse_registry_output(text):
    """Parse MODSLOT lines into occupied-slot records. Best-effort: a slot
    counts as occupied iff the name is non-empty and text.addr is non-zero.
    Returns [{name, version, sha1, text, data, bss, rodata}] with int addresses.
    """
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


def read_registry(runner):
    """Read `s_mod_map` via two passes of debugger commands.

    `runner(commands) -> str` executes a list of debugger commands against the
    program and core and returns the combined output. Injected rather than
    performed here so the same protocol serves the sandboxed service (where the
    debugger runs jailed and the paths are jail-relative) and the local CLI.

    Returns occupied-slot records, possibly empty. Never raises for a missing
    symbol: firmware without a module registry is a normal case.
    """
    out = runner([nslots_printf()])
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
    return parse_registry_output(runner([slot_printf(i) for i in range(n)]))


def render_add_symbols(templates, modules):
    """Render a toolchain's symbol-loading commands for each resolved module.

    `templates` comes from the descriptor, so the debugger syntax is the
    toolchain's business rather than this module's. Each module dict supplies
    `elf` plus the section addresses; addresses are formatted as hex by the
    template (`{text:#x}`) so the debugger never has to evaluate the registry
    itself.
    """
    fields = _template_fields(templates)
    commands = []
    for module in modules:
        values = {k: v for k, v in module.items() if k in fields}
        for template in templates:
            commands.append(template.format(**values))
    return commands


def _template_fields(templates):
    names = set()
    for template in templates:
        for _lit, field, _spec, _conv in string.Formatter().parse(template):
            if field:
                names.add(field.split(".")[0].split("[")[0])
    return names


def addsym_commands(modules):
    """The default gdb rendering, for callers with no descriptor - i.e. the
    local CLI."""
    return render_add_symbols(DEFAULT_ADD_SYMBOLS, modules)


def write_addsym_gdbinit(modules, path=None):
    """Write symbol-loading commands to a file the debugger can source.

    With `path`, writes there and returns it; without, writes a temp file the
    caller owns (the CLI's usage).
    """
    commands = addsym_commands(modules)
    if path is None:
        fd, path = tempfile.mkstemp(suffix=".gdbinit", prefix="modsym_")
        os.close(fd)
    with open(path, "w") as f:
        f.write("\n".join(commands))
        if commands:
            f.write("\n")
    return path
