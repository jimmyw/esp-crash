"""Sandbox construction tests: pure argv/spec assertions, no Docker, no gdb.

Written in the same style as test_decode_module_coredump.py - feed the builder
a synthetic descriptor and assert on the strings it produces. That matters more
than it might look: every property asserted here is a security property whose
absence is silent. A missing --unshare flag, a --bind where a --ro-bind was
meant, or a writable jail root all leave a sandbox that works perfectly and
protects nothing, so they cannot be left to a passing end-to-end run.
"""
import pytest

import toolchains
from gdb_app import jail


@pytest.fixture
def tc():
    return toolchains.Toolchain(
        name="fake-elf", arch="fakearch", version="1.0",
        exe="/opt/tc/bin/fake-gdb", converter="passthrough",
        libs=("/lib/x86_64-linux-gnu/libc.so.6", "/lib64/ld-linux-x86-64.so.2"),
        extra=("/opt/tc/share/data",),
        env={"FAKE_ROM_DIR": "/opt/tc/share/data"},
    )


@pytest.fixture
def spec(tc):
    return jail.JailSpec(toolchain=tc, workdir="/run/gdb/abc", uid=100007, gid=100007)


def argv_of(spec, command=("/opt/tc/bin/fake-gdb",)):
    return jail.argv(spec, list(command))


def pairs(argv, flag):
    """Every (src, dst) for a given bind flag, so a --bind cannot hide among
    the --ro-binds."""
    return [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == flag]


# --------------------------------------------------------------- isolation

def test_uses_hard_unshare_flags_not_the_try_variants(spec):
    argv = argv_of(spec)
    for flag in ("--unshare-user", "--unshare-ipc", "--unshare-pid",
                 "--unshare-net", "--unshare-uts", "--unshare-cgroup"):
        assert flag in argv, f"{flag} missing - namespace not isolated"
    # --unshare-all silently degrades: it maps to the "-try" variants for the
    # user and cgroup namespaces, so a kernel without them yields a sandbox
    # with no user namespace at all and no error.
    assert "--unshare-all" not in argv
    assert not any(a.endswith("-try") for a in argv)


def test_root_is_an_empty_tmpfs_and_ends_read_only(spec):
    argv = argv_of(spec)
    assert ["--tmpfs", "/"] == argv[argv.index("--tmpfs"):argv.index("--tmpfs") + 2]
    # The remount must come after every bind, or the binds fail; and without it
    # the private root stays writable.
    assert argv.index("--remount-ro") > max(
        i for i, a in enumerate(argv) if a in ("--ro-bind", "--bind"))


def test_only_the_session_workdir_is_writable(spec):
    argv = argv_of(spec)
    assert pairs(argv, "--bind") == [("/run/gdb/abc", jail.WORK)]


def test_every_toolchain_path_is_bound_read_only(spec, tc):
    ro = dict(pairs(argv_of(spec), "--ro-bind"))
    for path in (tc.exe, *tc.libs, *tc.extra):
        assert ro.get(path) == path, f"{path} not bound read-only at its own path"


def test_no_proc_is_mounted(spec):
    # gdb reading a core file does not need /proc, and mounting one would both
    # require a container privilege we do not take and give a session something
    # to enumerate.
    assert "--proc" not in argv_of(spec)


def test_drops_capabilities_clears_env_and_detaches(spec):
    argv = argv_of(spec)
    assert argv[argv.index("--cap-drop") + 1] == "ALL"
    assert "--clearenv" in argv
    assert "--die-with-parent" in argv
    # setsid: without it a sandboxed process can inject into our controlling
    # terminal via TIOCSTI, which matters because the session tier gets a pty.
    assert "--new-session" in argv


def test_does_not_ask_bwrap_to_map_a_different_uid(spec):
    # The caller setuid()s to the pool uid before exec, so an identity map is
    # all that is needed. Asking for --uid needs privileges bwrap will not have
    # at that point and fails with "setting up uid map: Operation not permitted".
    argv = argv_of(spec)
    assert "--uid" not in argv
    assert "--gid" not in argv


# ------------------------------------------------------------- environment

def test_jail_env_is_built_from_scratch_and_carries_toolchain_env(spec):
    env = spec.jail_env()
    assert env["FAKE_ROM_DIR"] == "/opt/tc/share/data"
    assert env["HOME"] == jail.WORK
    # / is read-only, so scratch space must point at the one writable mount.
    assert env["TMPDIR"] == jail.WORK


def test_library_path_covers_bound_libraries(spec):
    # We do not bind /etc/ld.so.cache, so anything outside ld.so's default
    # directories is only found via LD_LIBRARY_PATH.
    assert "/lib64" in spec.library_path().split(":")
    assert "/lib/x86_64-linux-gnu" in spec.library_path().split(":")


def test_library_path_ignores_non_library_binds(tc):
    spec = jail.JailSpec(toolchain=tc, workdir="/w", uid=1, gid=1,
                         extra_ro=("/usr/local/lib/python3.12",))
    assert "/usr/local/lib" not in spec.library_path().split(":")


def test_converter_binds_are_included_in_the_convert_tier(tc):
    spec = jail.JailSpec(toolchain=tc, workdir="/w", uid=1, gid=1,
                         tier=jail.CONVERT, extra_ro=("/usr/local/bin/python3.12",))
    ro = dict(pairs(argv_of(spec), "--ro-bind"))
    assert ro["/usr/local/bin/python3.12"] == "/usr/local/bin/python3.12"


def test_binds_are_deduplicated_and_ordered(tc):
    spec = jail.JailSpec(toolchain=tc, workdir="/w", uid=1, gid=1,
                         extra_ro=(tc.exe, "/opt/tc/share/data"))
    binds = pairs(argv_of(spec), "--ro-bind")
    assert len(binds) == len(set(binds))


# --------------------------------------------------- hostile toolchain names

@pytest.mark.parametrize("name", [
    "../../etc", "/etc/shadow", "xtensa-esp-elf/../../..", "..",
    "", None, "does-not-exist",
])
def test_a_toolchain_name_from_the_database_cannot_reach_the_filesystem(name, monkeypatch):
    # project_settings.toolchain is user-editable and selects paths for a
    # sandbox, so resolution is a dictionary lookup over what the image
    # actually installed - never interpolation into a path.
    monkeypatch.setattr(toolchains, "installed", lambda: {"real-one": object()})
    assert toolchains.get(name) is None


def test_a_known_toolchain_name_resolves(monkeypatch):
    sentinel = object()
    monkeypatch.setattr(toolchains, "installed", lambda: {"real-one": sentinel})
    assert toolchains.get("real-one") is sentinel
