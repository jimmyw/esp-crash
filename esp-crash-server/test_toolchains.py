"""Toolchain descriptor tests: parsing, variants, validation, and the
vendor-neutral seam.

Descriptors are read at runtime from a mounted directory and they name commands
to execute, so parsing them is a security-relevant surface: a malformed one must
fail loudly rather than yield a half-configured sandbox, and a value from a
descriptor must never be able to reach outside its package or inject an
argument.

The project is also expanding past Espressif to other ARM and RISC-V chips, so
several tests exist purely to keep ESP assumptions out of the loader. The
strongest of them builds a descriptor with no conversion step, no module
registry and no interpreter, and asserts it produces a working toolchain -
because that is exactly the shape a plain ELF-core ARM target has.
"""
import textwrap

import pytest

import toolchains

MINIMAL = """\
schema: 1
name: fake-elf
arch: fakearch
version: "1.0"
debugger: bin/fake-gdb
interactive:
  command: ["{debugger}", -q, "{prog}", -ex, "core-file {core}"]
"""


def write_package(tmp_path, dirname, body=MINIMAL, extra="", exe="bin/fake-gdb"):
    """Create a package directory with a descriptor and a dummy debugger.

    `extra` is dedented and appended; `body` is not. Only the appended blocks
    are indented in the test source, so dedenting the concatenation would find
    no common prefix and silently do nothing - which produces malformed YAML
    rather than an error.
    """
    pkg = tmp_path / dirname
    (pkg / "bin").mkdir(parents=True)
    if exe:
        target = pkg / exe
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("#!/bin/sh\necho 'GNU gdb (fake) 1.0'\n")
        target.chmod(0o755)
    (pkg / toolchains.DESCRIPTOR_NAME).write_text(body + textwrap.dedent(extra))
    return pkg


@pytest.fixture(autouse=True)
def _fresh_caches(monkeypatch, tmp_path):
    toolchains.installed.cache_clear()
    monkeypatch.setenv("GDB_TOOLCHAIN_ROOTS", str(tmp_path))
    yield
    toolchains.installed.cache_clear()


# ------------------------------------------------------------------ discovery

def test_discovers_a_package(tmp_path):
    write_package(tmp_path, "one")
    found = toolchains.installed()
    assert set(found) == {"fake-elf"}
    assert found["fake-elf"].arch == "fakearch"


def test_a_dropped_in_package_is_visible_without_a_restart(tmp_path):
    """The whole point of runtime descriptors: `installed()` must not be
    memoised across calls, or mounting a new package would need a redeploy."""
    assert toolchains.installed() == {}
    write_package(tmp_path, "later")
    assert set(toolchains.installed()) == {"fake-elf"}


def test_variants_become_distinct_toolchain_ids(tmp_path):
    write_package(tmp_path, "esp", extra="""\
        variants:
          fake-chipA:
            chip: chipA
            env: { CORE_CONFIG: "{root}/bin/a.so" }
          fake-chipB:
            chip: chipB
            env: { CORE_CONFIG: "{root}/bin/b.so" }
        """)
    found = toolchains.installed()
    assert set(found) == {"fake-chipA", "fake-chipB"}
    # One payload, several ids: the shared fields must be identical...
    assert found["fake-chipA"].exe == found["fake-chipB"].exe
    # ...and only the per-variant environment differs.
    assert found["fake-chipA"].chip == "chipA"
    assert found["fake-chipA"].env["CORE_CONFIG"].endswith("/bin/a.so")
    assert found["fake-chipB"].env["CORE_CONFIG"].endswith("/bin/b.so")


def test_root_is_expanded_to_the_package_directory(tmp_path):
    pkg = write_package(tmp_path, "one", extra="""\
        env:
          DATA_DIR: "{root}/share"
        binds: ["{root}/extra"]
        """)
    tc = toolchains.get("fake-elf")
    assert tc.env["DATA_DIR"] == f"{pkg}/share"
    assert tc.binds == (f"{pkg}/extra",)
    # `{root}` must never survive into a value that reaches a command line.
    assert "{root}" not in str(tc.env) + str(tc.binds)


# ----------------------------------------------------------------- validation

def test_an_unsupported_schema_is_refused(tmp_path):
    write_package(tmp_path, "one", body=MINIMAL.replace("schema: 1", "schema: 99"))
    with pytest.raises(toolchains.DescriptorError, match="unsupported schema"):
        toolchains.installed()


@pytest.mark.parametrize("key", ["name", "arch", "version", "debugger"])
def test_a_missing_required_key_is_a_loud_failure(tmp_path, key):
    body = "\n".join(l for l in MINIMAL.splitlines() if not l.startswith(f"{key}:"))
    write_package(tmp_path, "one", body=body)
    with pytest.raises(toolchains.DescriptorError, match=key):
        toolchains.installed()


def test_interactive_is_required(tmp_path):
    write_package(tmp_path, "one", body=MINIMAL.split("interactive:")[0])
    with pytest.raises(toolchains.DescriptorError, match="interactive"):
        toolchains.installed()


def test_an_unknown_placeholder_is_refused(tmp_path):
    """A typo would otherwise reach a command line as a literal and fail far
    away from its cause."""
    write_package(tmp_path, "one", body=MINIMAL.replace('"{prog}"', '"{prorgam}"'))
    with pytest.raises(toolchains.DescriptorError, match="unknown placeholder"):
        toolchains.installed()


def test_python_placeholder_is_only_allowed_when_declared(tmp_path):
    write_package(tmp_path, "one", extra="""\
        report:
          commands:
            - ["{python}", -m, something]
        """)
    with pytest.raises(toolchains.DescriptorError, match="unknown placeholder"):
        toolchains.installed()


def test_a_command_must_be_a_list_not_a_shell_string(tmp_path):
    """Commands are substituted per element and executed without a shell, so a
    string here is a category error - and accepting one would open the door to
    argument injection from descriptor values."""
    write_package(tmp_path, "one", extra="""\
        report:
          commands:
            - "{debugger} -batch -ex bt"
        """)
    with pytest.raises(toolchains.DescriptorError, match="argv lists"):
        toolchains.installed()


def test_a_debugger_path_cannot_escape_the_package(tmp_path):
    write_package(tmp_path, "one", body=MINIMAL.replace("debugger: bin/fake-gdb",
                                  "debugger: ../../../usr/bin/gdb"))
    with pytest.raises(toolchains.DescriptorError, match="escapes the package"):
        toolchains.installed()


def test_a_declared_phase_with_no_commands_is_refused(tmp_path):
    write_package(tmp_path, "one", extra="report:\n  timeout: 10\n")
    with pytest.raises(toolchains.DescriptorError, match="no commands"):
        toolchains.installed()


# ------------------------------------------------------- rendering & binds

def test_render_substitutes_per_element(tmp_path):
    write_package(tmp_path, "one")
    tc = toolchains.get("fake-elf")
    argv, = tc.render(tc.interactive, {
        "debugger": "/pkg/bin/gdb", "prog": "prog.elf", "core": "core.elf",
    })
    assert argv == ["/pkg/bin/gdb", "-q", "prog.elf", "-ex", "core-file core.elf"]


def test_with_symbols_is_appended_only_when_asked(tmp_path):
    write_package(tmp_path, "one", extra="""\
        report:
          with_symbols: [-x, "{symbols_file}"]
          commands:
            - ["{debugger}", -batch, "{prog}"]
        """)
    tc = toolchains.get("fake-elf")
    subst = {"debugger": "gdb", "prog": "p.elf", "symbols_file": "syms.gdbinit"}
    assert tc.render(tc.report, subst) == [["gdb", "-batch", "p.elf"]]
    assert tc.render(tc.report, subst, with_symbols=True) == \
        [["gdb", "-batch", "p.elf", "-x", "syms.gdbinit"]]


def test_ro_binds_covers_the_package_and_declared_binds(tmp_path):
    pkg = write_package(tmp_path, "one", extra=f'binds: ["{tmp_path}/outside"]\n')
    (tmp_path / "outside").mkdir()
    binds = toolchains.get("fake-elf").ro_binds
    assert str(pkg) in binds, "the package directory itself must be bound"
    assert f"{tmp_path}/outside" in binds
    # Nothing inside the package needs a separate bind - it is covered already.
    assert not any(b.startswith(str(pkg) + "/") for b in binds)


# ------------------------------------------- the vendor-neutral seam

ARM_LIKE = """\
schema: 1
name: arm-none-eabi
arch: arm
version: "10.2"
description: a target whose artifact already is a core file
debugger: bin/fake-gdb
report:
  commands:
    - ["{debugger}", -batch, "{prog}", -ex, "core-file {core}", -ex, "bt"]
interactive:
  command: ["{debugger}", -q, "{prog}", -ex, "core-file {core}"]
"""


def test_a_target_needing_no_conversion_no_modules_and_no_interpreter(tmp_path):
    """The ARM/EFR32 shape: its crash artifact is already an ELF core, it has no
    runtime module registry, and nothing in its package needs Python. All three
    are expressed by omission - if this needs code changes, the seam has leaked.
    """
    write_package(tmp_path, "arm", body=ARM_LIKE)
    tc = toolchains.get("arm-none-eabi")
    assert tc.core is None, "no conversion step declared"
    assert tc.modules is None, "no module registry declared"
    assert tc.python is None, "no interpreter bundled"
    assert tc.report is not None and tc.interactive is not None

    joined = " ".join(sum((list(c) for c in tc.report.commands), []))
    for esp in ("esp_coredump", "esp-coredump", "xtensa", "ESP_ROM_ELF_DIR", "IDF_PATH"):
        assert esp not in joined, f"{esp!r} leaked into a non-ESP toolchain"


def test_modules_section_is_parsed_when_present(tmp_path):
    write_package(tmp_path, "one", extra="""\
        modules:
          registry: esp_crash_modmap
          batch: ["{debugger}", -batch, "{prog}"]
          add_symbols:
            - "add-symbol-file {elf} {text:#x} -s .data {data:#x}"
        """)
    modules = toolchains.get("fake-elf").modules
    assert modules.registry == "esp_crash_modmap"
    # The debugger syntax for loading symbols is descriptor data, not code -
    # lldb would say `target modules add`.
    assert "add-symbol-file" in modules.add_symbols[0]


def test_module_placeholders_are_only_allowed_inside_add_symbols(tmp_path):
    write_package(tmp_path, "one", body=MINIMAL.replace('"{prog}"', '"{text}"'))
    with pytest.raises(toolchains.DescriptorError, match="unknown placeholder"):
        toolchains.installed()


# ----------------------------------------------------------- hostile names

@pytest.mark.parametrize("name", [
    "../../etc", "/etc/shadow", "fake-elf/../../..", "..", "", None, "nope",
])
def test_a_name_from_the_database_cannot_reach_the_filesystem(tmp_path, name):
    write_package(tmp_path, "one")
    assert toolchains.get(name) is None


def test_names_lists_every_variant(tmp_path):
    write_package(tmp_path, "esp", extra="""\
        variants:
          b-chip: {}
          a-chip: {}
        """)
    assert toolchains.names() == ["a-chip", "b-chip"]
