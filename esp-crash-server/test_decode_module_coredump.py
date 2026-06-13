import decode_module_coredump as d


def test_parse_registry_output_reads_occupied_slot():
    out = (
        "some gdb banner\n"
        "MODSLOT|0|ems_goodwe|907577e48f4fe8b69a2e92468dbade2d72a5ea28|"
        "1076484860|1073651168|1073651216|1062290960\n"
        "MODSLOT|1||0|0|0|0\n"  # free slot
    )
    mods = d.parse_registry_output(out)
    assert mods == [{
        "name": "ems_goodwe",
        "sha1": "907577e48f4fe8b69a2e92468dbade2d72a5ea28",
        "text": 1076484860, "data": 1073651168,
        "bss": 1073651216, "rodata": 1062290960,
    }]


def test_parse_registry_output_skips_free_and_midload_slots():
    out = (
        "MODSLOT|0||0|0|0|0\n"               # free: empty name
        "MODSLOT|1|loading|ab|0|10|20|30\n"  # mid-load: text.addr == 0
    )
    assert d.parse_registry_output(out) == []


def test_parse_registry_output_no_slots_returns_empty():
    assert d.parse_registry_output("nothing here\n") == []


def test_parse_registry_output_ignores_malformed_lines():
    out = "MODSLOT|0|x\nMODSLOT|0|x|aa|notanint|0|0|0\n"
    assert d.parse_registry_output(out) == []


def test_parse_elf_map_arg_splits_name_path():
    assert d.parse_elf_map_arg("ems-goodwe=/t/x.app.elf") == ("ems-goodwe", "/t/x.app.elf")


def test_parse_elf_map_arg_keeps_equals_in_path():
    assert d.parse_elf_map_arg("m=/t/a=b.elf") == ("m", "/t/a=b.elf")


def test_parse_elf_map_arg_requires_equals():
    try:
        d.parse_elf_map_arg("no-equals")
    except ValueError:
        return
    raise AssertionError("expected ValueError for spec without '='")


def test_addsym_commands_emits_literal_hex_sections():
    loaded = [{
        "name": "ems_goodwe", "sha1": "aa", "elf": "/t/mod.elf",
        "text": 0x4029dafc, "data": 0x3ffb3260,
        "bss": 0x3ffb3290, "rodata": 0x3f4264d0,
    }]
    cmds = d.addsym_commands(loaded)
    assert cmds == [
        "add-symbol-file /t/mod.elf 0x4029dafc -s .data 0x3ffb3260 "
        "-s .bss 0x3ffb3290 -s .rodata 0x3f4264d0"
    ]


def test_addsym_commands_empty_for_no_modules():
    assert d.addsym_commands([]) == []


def test_write_addsym_gdbinit_writes_literal_lines():
    import os
    loaded = [{
        "name": "m", "sha1": "aa", "elf": "/t/m.elf",
        "text": 0x10, "data": 0x20, "bss": 0x30, "rodata": 0x40,
    }]
    p = d.write_addsym_gdbinit(loaded)
    try:
        with open(p) as f:
            content = f.read()
        assert content == (
            "add-symbol-file /t/m.elf 0x10 -s .data 0x20 "
            "-s .bss 0x30 -s .rodata 0x40\n"
        )
    finally:
        os.unlink(p)


def test_write_addsym_gdbinit_empty_for_no_modules():
    import os
    p = d.write_addsym_gdbinit([])
    try:
        with open(p) as f:
            assert f.read() == ""
    finally:
        os.unlink(p)
