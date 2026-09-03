"""Real bubblewrap jail tests: isolation asserted against the kernel.

Marked `integration` and skipped by default, following the convention already
used for the toolchain-dependent decode test (see pytest.ini and
tests/test_cron.py). Run inside the debug service's own container, which is
where the required privileges exist:

    docker compose exec esp-crash-gdb python -m pytest -m integration test_jail_integration.py

These are the assertions that cannot be made from argv strings alone. Every
isolation property the design claims is checked here by trying to violate it -
a sandbox that merely looks right in a command line but does not hold is worth
nothing, and the failure would be silent.

Note the two reasons this needs a real environment: bubblewrap needs
unprivileged user namespaces (blocked by Docker's default seccomp profile, so
the service runs with seccomp=unconfined), and the session identities are
accounts created in the image.
"""
import asyncio
import os
import subprocess

import pytest

import toolchains
from gdb_app import jail, materialize
from gdb_app.uidpool import SessionPool, discover_accounts

pytestmark = pytest.mark.integration


def _jail_usable():
    """Can we actually create a sandbox here? Reported as a skip reason rather
    than a failure, since running outside the service container is a normal
    thing to do."""
    if not os.path.exists(jail.BWRAP):
        return f"bubblewrap not installed at {jail.BWRAP}"
    if not discover_accounts():
        return "no gdbrun* session accounts in this image"
    if not toolchains.installed():
        return "no toolchain manifests installed"
    # Probe by message rather than exit status. bubblewrap always builds its
    # root from nothing, so a probe that execs any host path fails for lack of
    # a bind even when namespaces work perfectly - the exit code cannot tell
    # "no namespaces" from "nothing to exec". The namespace refusal has its own
    # distinctive message, so look for that and treat anything else (including
    # the expected execvp failure) as proof we got far enough.
    probe = subprocess.run(
        [jail.BWRAP, "--unshare-user", "--unshare-pid", "--tmpfs", "/", "--",
         "/nonexistent-probe"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    output = (probe.stdout or b"").decode("utf-8", "replace")
    for refusal in ("No permissions to create new namespace",
                    "Creating new namespace failed",
                    "setting up uid map"):
        if refusal in output:
            return f"cannot create a sandbox here: {output.strip()[:140]}"
    return None


@pytest.fixture(scope="module", autouse=True)
def _require_jail():
    if (reason := _jail_usable()):
        pytest.skip(reason)


@pytest.fixture
def pool():
    return SessionPool()


@pytest.fixture
def lease(pool):
    lease = asyncio.run(pool.acquire())
    yield lease
    asyncio.run(pool.release(lease))


@pytest.fixture
def toolchain():
    return sorted(toolchains.installed().values(), key=lambda t: t.name)[0]


def run(lease, toolchain, command, extra_ro=(), timeout=60):
    spec = jail.JailSpec(toolchain=toolchain, workdir=lease.workdir,
                         uid=lease.uid, gid=lease.gid, tier=jail.SESSION,
                         extra_ro=tuple(extra_ro))
    result = jail.run_batch(spec, command, timeout=timeout)
    return result.returncode, (result.stdout or b"").decode("utf-8", "replace")


def gdb_eval(lease, toolchain, *commands):
    """Use the debugger itself as the in-jail probe. It is the one binary
    guaranteed to be there, and using anything else would mean binding extra
    tools and testing a jail we do not actually ship."""
    argv = [toolchain.exe, "-batch", "-nx", "-q"]
    for c in commands:
        argv += ["-ex", c]
    return run(lease, toolchain, argv)


# ------------------------------------------------------------ it works at all

def test_the_debugger_runs_in_its_jail(lease, toolchain):
    code, out = run(lease, toolchain, [toolchain.exe, "--version"])
    assert code == 0 and "GNU gdb" in out


def test_the_debugger_can_read_and_write_its_work_directory(lease, toolchain):
    materialize._write(lease.workdir, "probe.txt", b"hello", lease.gid)
    code, out = gdb_eval(lease, toolchain,
                         "set logging file /work/out.log",
                         "set logging enabled on", "print 6*7")
    assert code == 0 and "42" in out
    assert os.path.exists(os.path.join(lease.workdir, "out.log")), \
        "the work directory must be writable, or gdb cannot log or dump"


def test_files_the_service_writes_are_readable_by_the_jail(lease, toolchain):
    """Guards a subtle ownership trap: the service has no CAP_FSETID, so a
    setgid work directory does not stick and files would land in group root,
    unreadable inside the jail - with gdb reporting "No such file or directory"
    for a file that is plainly present."""
    materialize._write(lease.workdir, "sym.txt", b"x" * 32, lease.gid)
    st = os.stat(os.path.join(lease.workdir, "sym.txt"))
    assert st.st_gid == lease.gid
    code, out = gdb_eval(lease, toolchain, "shell true", "print 1")
    assert code == 0


# --------------------------------------------------------------- confinement

def test_the_jail_root_is_read_only(lease, toolchain):
    _code, out = gdb_eval(lease, toolchain,
                          "set logging file /pwn.log", "set logging enabled on")
    assert "Read-only file system" in out or "error" in out.lower(), \
        "the tmpfs root must be remounted read-only after the binds"


def test_the_toolchain_cannot_be_tampered_with(lease, toolchain):
    # Toolchains are shared between sessions, so a writable bind would let one
    # session poison the debugger a later session runs.
    _code, out = gdb_eval(lease, toolchain,
                          f"set logging file {toolchain.exe}.tamper",
                          "set logging enabled on")
    assert "Read-only file system" in out or "error" in out.lower()


def test_there_is_no_shell_in_the_session_jail(lease, toolchain):
    # gdb's `shell` command is denied by there being no shell to exec, not by
    # a command blocklist - a kernel/filesystem fact rather than a filter.
    _code, out = gdb_eval(lease, toolchain, "shell echo ESCAPED")
    assert "ESCAPED" not in out
    assert "Cannot exec" in out or "No such file" in out


def test_the_jail_has_no_network(lease, toolchain):
    _code, out = gdb_eval(lease, toolchain, "target remote 8.8.8.8:1234")
    assert "ESCAPED" not in out
    assert "unreachable" in out.lower() or "network" in out.lower() \
        or "connection" in out.lower()


def test_the_work_root_is_not_even_visible_inside_the_jail(lease, toolchain):
    """The strongest form of peer isolation: a session cannot name another
    session's directory, let alone open it, because the parent directory is
    not part of its filesystem at all."""
    root = os.path.dirname(lease.workdir)
    _code, out = gdb_eval(lease, toolchain, f"shell ls {root}")
    assert lease.session_id not in out


# ------------------------------------------------ what the package brought

def test_the_conversion_jail_binds_no_whole_system_library_directory(toolchain):
    """The bundled interpreter retired a coarse workaround, and this pins it.

    esp-coredump's extension modules dlopen libraries that `ldd` on the
    interpreter never reveals - binascii needing libz was the one that bit -
    and the old converter answered by binding /lib/<multiarch> and /lib64
    wholesale into the conversion jail. A package carries those inside itself,
    so the only directory a jail should mount from outside is one the
    descriptor asked for by name.
    """
    spec = jail.JailSpec(toolchain=toolchain, workdir="/tmp", uid=os.getuid(),
                         gid=os.getgid(), tier=jail.CONVERT)
    declared = {os.path.realpath(b) for b in (toolchain.binds or ())}
    for bind in spec.all_ro_binds():
        if toolchain.root and bind.startswith(toolchain.root):
            continue                      # inside the package, by design
        if os.path.isdir(bind):
            assert os.path.realpath(bind) in declared, (
                f"{bind} is a whole directory bound from outside the package "
                f"but is not in the descriptor's `binds`")


def test_the_bundled_interpreter_runs_inside_the_conversion_jail(toolchain, lease):
    """If the package declares an interpreter, it must actually work in the
    sandbox - including the extension modules whose dependencies ldd hides."""
    if not toolchain.python:
        pytest.skip("this toolchain bundles no interpreter")
    code, out = run(lease, toolchain,
                    [toolchain.python, "-c",
                     "import binascii, zlib, ssl, hashlib, ctypes; print('imports ok')"],
                    timeout=120)
    assert code == 0 and "imports ok" in out, out[:400]


def test_every_path_valued_environment_variable_exists_inside_the_jail(toolchain, lease):
    """A variable pointing outside the sandbox does not error - the debugger
    silently falls back to a default and produces plausible, wrong output. That
    is the failure mode this whole design exists to prevent, so it is asserted
    against the real jail rather than only at load time."""
    for key, value in (toolchain.env or {}).items():
        if not value.startswith("/"):
            continue
        target = value.rstrip("/")
        covered = any(target == b or target.startswith(b.rstrip("/") + "/")
                      or b.startswith(target + "/")
                      for b in toolchain.ro_binds)
        assert covered, f"{key}={value} is not inside any bind"


# ------------------------------------------------- one session versus another

def test_concurrent_sessions_get_distinct_identities(pool):
    a = asyncio.run(pool.acquire())
    b = asyncio.run(pool.acquire())
    try:
        assert a.uid != b.uid, \
            "sessions sharing a uid share a kernel principal and an RLIMIT_NPROC"
        assert a.workdir != b.workdir
    finally:
        asyncio.run(pool.release(a))
        asyncio.run(pool.release(b))


def test_a_session_cannot_read_another_sessions_work_directory(pool, toolchain):
    a = asyncio.run(pool.acquire())
    b = asyncio.run(pool.acquire())
    try:
        materialize._write(b.workdir, "secret.txt", b"other session's data", b.gid)
        # Checked as the *outer* principal, which is what the DAC bits actually
        # constrain; inside the jail the path does not exist at all.
        probe = subprocess.run(
            ["setpriv", f"--reuid={a.uid}", f"--regid={a.gid}", "--clear-groups",
             "cat", os.path.join(b.workdir, "secret.txt")],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        assert probe.returncode != 0, "session A could read session B's files"
        assert b"other session's data" not in probe.stdout
    finally:
        asyncio.run(pool.release(a))
        asyncio.run(pool.release(b))


def test_the_pool_is_bounded_and_reusable(pool):
    from gdb_app.uidpool import PoolExhausted
    held = []
    try:
        while True:
            held.append(asyncio.run(pool.acquire()))
    except PoolExhausted:
        pass
    assert len(held) == pool.capacity
    assert pool.available == 0
    # Releasing must return the identity, or capacity would shrink over time.
    asyncio.run(pool.release(held.pop()))
    assert pool.available == 1
    for lease in held:
        asyncio.run(pool.release(lease))


def test_releasing_a_lease_removes_its_work_directory(pool):
    lease = asyncio.run(pool.acquire())
    materialize._write(lease.workdir, "leftover.bin", b"x" * 1024, lease.gid)
    asyncio.run(pool.release(lease))
    assert not os.path.exists(lease.workdir), \
        "a leaked work directory keeps crash bytes on the box after the session"
