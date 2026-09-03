"""Toolchain-descriptor tests, including the vendor-neutral seam.

The project is expanding past Espressif to other ARM and RISC-V chips, so the
descriptor and converter layers must not acquire ESP assumptions. The
synthetic non-ESP toolchain below is the guard for that: it asserts a
descriptor with a different architecture and a different converter produces a
valid jail with no Espressif anything, which is checkable today, long before
there is real hardware to test against.
"""
import json

import pytest

import toolchains
from gdb_app import converters, jail


def write_manifest(tmp_path, dirname, **overrides):
    """Write a synthetic manifest under tmp_path/<dirname>/1.0/.

    `dirname` is the directory, not necessarily the toolchain name - the two
    differ in the malformed-manifest tests, which blank out `name` itself.
    """
    manifest = {
        "name": dirname, "arch": "xtensa", "version": "1.0",
        "exe": "/opt/tc/bin/gdb", "converter": "esp_coredump",
        "libs": ["/lib/libc.so.6"], "extra": [], "env": {},
    }
    manifest.update(overrides)
    d = tmp_path / dirname / "1.0"
    d.mkdir(parents=True)
    (d / toolchains.MANIFEST_NAME).write_text(json.dumps(manifest))
    return d


@pytest.fixture(autouse=True)
def _fresh_cache():
    toolchains.installed.cache_clear()
    yield
    toolchains.installed.cache_clear()


def test_discovers_manifests_under_the_configured_roots(tmp_path, monkeypatch):
    write_manifest(tmp_path, "one")
    write_manifest(tmp_path, "two", arch="riscv32")
    monkeypatch.setenv("GDB_TOOLCHAIN_ROOTS", str(tmp_path))
    found = toolchains.discover()
    assert set(found) == {"one", "two"}
    assert found["two"].arch == "riscv32"


def test_multiple_roots_are_searched_with_the_first_winning(tmp_path, monkeypatch):
    a, b = tmp_path / "a", tmp_path / "b"
    write_manifest(a, "same", version="from-a")
    write_manifest(b, "same", version="from-b")
    monkeypatch.setenv("GDB_TOOLCHAIN_ROOTS", f"{a}:{b}")
    assert toolchains.discover()["same"].version == "from-a"


@pytest.mark.parametrize("missing", ["name", "arch", "version", "exe", "converter"])
def test_an_incomplete_manifest_is_a_loud_failure(tmp_path, monkeypatch, missing):
    # Generated at build time, so a malformed one means the build is broken;
    # failing loudly beats a half-configured sandbox.
    write_manifest(tmp_path, "broken", **{missing: ""})
    monkeypatch.setenv("GDB_TOOLCHAIN_ROOTS", str(tmp_path))
    with pytest.raises(ValueError, match=missing):
        toolchains.discover()


def test_ro_binds_covers_exe_libs_and_extra_without_duplicates():
    tc = toolchains.Toolchain(
        name="t", arch="a", version="1", exe="/x/gdb", converter="passthrough",
        libs=("/lib/a.so", "/lib/a.so"), extra=("/x/gdb", "/data"),
    )
    assert tc.ro_binds == ("/x/gdb", "/lib/a.so", "/data")


# ------------------------------------------------- the vendor-neutral seam

def test_a_non_esp_toolchain_produces_a_valid_jail_with_no_esp_anything():
    arm = toolchains.Toolchain(
        name="arm-none-eabi", arch="arm", version="14.2",
        exe="/opt/arm/bin/arm-none-eabi-gdb", converter="passthrough",
        libs=("/lib/x86_64-linux-gnu/libc.so.6",), extra=(), env={},
    )
    spec = jail.JailSpec(toolchain=arm, workdir="/run/gdb/x", uid=1, gid=1)
    argv = jail.argv(spec, [arm.exe])

    assert "/opt/arm/bin/arm-none-eabi-gdb" in argv
    # No Espressif path, variable or tool may appear for a non-ESP target.
    joined = " ".join(argv)
    for esp in ("/opt/esp", "ESP_ROM_ELF_DIR", "IDF_PATH", "esp-coredump", "xtensa"):
        assert esp not in joined, f"{esp!r} leaked into a non-ESP jail"


def test_the_passthrough_converter_needs_no_extra_binds():
    # The point of the seam: a target that uploads a real core file never pulls
    # a Python runtime into any jail.
    assert converters.get("passthrough").extra_ro_binds() == ()


def test_the_esp_converter_declares_a_python_runtime():
    binds = converters.get("esp_coredump").extra_ro_binds()
    assert any("python" in b for b in binds), \
        "esp-coredump is a Python program; its jail must carry an interpreter"


@pytest.mark.parametrize("name", ["", "nope", "../etc/passwd", "os"])
def test_an_unknown_converter_name_cannot_import_anything(name):
    # The converter name comes from a manifest; resolving it must not become an
    # arbitrary import.
    with pytest.raises(converters.UnknownConverter):
        converters.get(name)


def test_every_known_converter_implements_the_contract():
    for name in converters.KNOWN:
        module = converters.get(name)
        assert callable(module.extra_ro_binds)
        assert callable(module.convert)
