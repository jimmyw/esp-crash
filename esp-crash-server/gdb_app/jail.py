"""Bubblewrap sandbox construction. No database, no WebSocket, no HTTP.

Every debugger process this service starts runs inside a jail built here. The
jail's root is an empty tmpfs with only an explicitly enumerated set of
read-only binds on top, so it is chroot-equivalent with nothing implicit: a
session can see the debugger, the libraries it links, its own work directory,
and nothing else.

Two tiers, because the untrusted-input parsing and the interactive console have
very different lifetimes (see `run_batch` and `spawn_pty`). The security
properties that make one session unable to reach another are:

  * a distinct kernel principal per live session - the caller `setuid()`s to a
    dedicated pool uid before exec, so cross-session ptrace/kill is EPERM and
    the per-uid RLIMIT_NPROC becomes a real per-session fork-bomb guard;
  * separate user/pid/net/ipc/uts/cgroup namespaces, so peers cannot be
    enumerated, signalled, or reached over a socket;
  * a work directory that is the only writable path, and whose parent is not
    even present inside the jail, so peers cannot be named;
  * read-only toolchain binds, so one session cannot poison the debugger a
    later session will run.

Several details here are load-bearing and were determined by experiment rather
than chosen; each is commented with what breaks without it.
"""
import fcntl
import os
import pty
import resource
import signal
import struct
import subprocess
import termios
from dataclasses import dataclass, field

BWRAP = "/usr/bin/bwrap"

# Where the session work directory appears inside the jail. Everything the
# debugger reads or writes lives under here.
WORK = "/work"

SESSION = "session"
CONVERT = "convert"


@dataclass(frozen=True)
class Limits:
    """Per-process rlimits applied in the child before exec.

    Deliberately generous: these exist to convert a runaway or malicious
    debugger into a failed session rather than a degraded host, not to
    micro-manage legitimate work. Real cgroup accounting would be better but
    needs cgroup delegation into the container.
    """
    address_space: int = 3 * 1024 ** 3   # 3 GiB; gdb maps large ELFs
    cpu_seconds: int = 600               # CPU time, not wall clock: an idle
                                         # interactive session costs nothing
    file_size: int = 512 * 1024 ** 2     # caps `set logging`/`dump binary`
    processes: int = 64                  # per-UID, hence per-session

    def apply(self):
        resource.setrlimit(resource.RLIMIT_AS, (self.address_space,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (self.cpu_seconds,) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (self.file_size,) * 2)
        resource.setrlimit(resource.RLIMIT_NPROC, (self.processes,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


@dataclass(frozen=True)
class JailSpec:
    """Everything needed to build one jail.

    `workdir` is the host path of the session directory; it is bound at
    `/work` and is the only writable location. `extra_ro` carries binds a
    converter needs beyond the toolchain's own (a Python runtime, for
    instance) - which is why the interactive tier can stay tiny while the
    conversion tier is allowed to be fat.
    """
    toolchain: object          # toolchains.Toolchain
    workdir: str
    uid: int
    gid: int
    tier: str = SESSION
    extra_ro: tuple = ()
    env: dict = field(default_factory=dict)
    limits: Limits = Limits()

    def all_ro_binds(self):
        """Every read-only host path for this jail, deduplicated, order stable
        so the command line is diffable in tests."""
        seen = {}
        for p in (*self.toolchain.ro_binds, *self.extra_ro):
            seen[p] = None
        return tuple(seen)

    def library_path(self):
        """Directories to search for shared objects inside the jail.

        Necessary because we do not bind `/etc/ld.so.cache`: without the cache,
        ld.so falls back to the binary's RUNPATH and then the default
        directories, and anything living outside those (a Python runtime under
        `/usr/local/lib`, for instance) is reported as "cannot open shared
        object file" even though the bind is right there. Deriving the search
        path from the bind list keeps this self-maintaining - a future
        toolchain that ships libraries in an unusual place works with no
        change here.
        """
        dirs = {}
        for path in self.all_ro_binds():
            base = os.path.basename(path)
            if ".so" in base and not os.path.isdir(path):
                dirs[os.path.dirname(path)] = None
        return ":".join(dirs)

    def jail_env(self):
        """The complete environment inside the jail. Built from scratch (the
        jail is `--clearenv`) so nothing leaks in - notably not the database
        credentials this service holds."""
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": WORK,
            # `/` is remounted read-only below, so anything that wants scratch
            # space has to be pointed at the one writable directory.
            "TMPDIR": WORK,
            "TERM": "xterm-256color",
            # C.UTF-8 rather than C: it is built into glibc so it needs no
            # locale files in the jail, and it stops gdb warning that it
            # "could not convert ... to UTF-32" whenever it prints a char
            # array. The browser terminal is UTF-8 either way.
            "LC_ALL": "C.UTF-8",
        }
        if (libpath := self.library_path()):
            env["LD_LIBRARY_PATH"] = libpath
        env.update(getattr(self.toolchain, "env", {}) or {})
        env.update(self.env)
        return env


def argv(spec, command):
    """Full bwrap argv to run `command` (a list) inside `spec`'s jail.

    Order matters: the tmpfs root goes down first, then the read-only binds on
    top of it, then the writable work directory, and only then is the root
    remounted read-only - a remount placed earlier would make the later binds
    fail.
    """
    a = [BWRAP,
         # Explicit unshare flags rather than --unshare-all: that alias uses the
         # "-try" variants for the user and cgroup namespaces, which silently
         # continue when the namespace is unavailable. For a security boundary a
         # missing namespace must be a hard failure, not a downgrade.
         "--unshare-user",
         "--unshare-ipc",
         "--unshare-pid",
         "--unshare-net",
         "--unshare-uts",
         "--unshare-cgroup",
         # Kill the sandbox if this service dies, so sessions cannot outlive it.
         "--die-with-parent",
         # setsid(): stops TIOCSTI injection back into our controlling terminal,
         # which matters precisely because the session tier is handed a pty.
         "--new-session",
         "--cap-drop", "ALL",
         "--clearenv",
         # Empty root. Everything below is an explicit exception to "nothing".
         "--tmpfs", "/"]

    for k, v in sorted(spec.jail_env().items()):
        a += ["--setenv", k, v]

    # Bound at their original absolute paths: ld.so resolves the ELF
    # interpreter and DT_NEEDED entries by absolute path, so relocating them
    # would mean maintaining ld.so.conf or RPATH inside the sandbox.
    for path in spec.all_ro_binds():
        a += ["--ro-bind", path, path]

    # No --proc, on purpose. Docker's masked /proc paths trip the kernel's
    # mount_too_revealing check, so mounting a fresh procfs fails unless the
    # container also runs with systempaths=unconfined. gdb analysing a core
    # file does not need /proc at all, so omitting it drops a container
    # privilege *and* leaves a session with nothing to enumerate.
    a += ["--dev", "/dev"]

    a += ["--dir", WORK, "--bind", spec.workdir, WORK]

    # Without this the tmpfs root is writable and a session can litter its
    # private root (and charge the container's memory for it). /work stays
    # writable because it is a separate mount.
    a += ["--remount-ro", "/"]

    a += ["--chdir", WORK, "--"]
    return a + list(command)


def _child_setup(spec):
    """Runs in the forked child, before exec.

    Drops to the session's dedicated uid and applies the rlimits. bwrap itself
    then runs completely unprivileged - it only needs an identity uid mapping,
    which is why no --uid/--gid is passed and why the service's own
    capabilities are not required here.
    """
    def setup():
        os.setgid(spec.gid)
        os.setgroups([spec.gid])
        os.setuid(spec.uid)
        spec.limits.apply()
        os.umask(0o077)
    return setup


def run_batch(spec, command, timeout=120):
    """Run `command` in the jail to completion and capture its output.

    The conversion tier, and the entry point a future in-process decode
    endpoint would reuse. Always returns - a timeout is reported as a
    CompletedProcess with a non-zero return code rather than raised, because
    every caller's correct response is the same: treat the artifact as
    undecodable and say so.
    """
    try:
        return subprocess.run(
            argv(spec, command),
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=timeout, preexec_fn=_child_setup(spec),
        )
    except subprocess.TimeoutExpired as e:
        out = e.output or b""
        return subprocess.CompletedProcess(
            e.cmd, 124,
            out + f"\n# timed out after {timeout}s\n".encode(),
        )


class PtyJail:
    """A jailed process attached to a pty, for the interactive tier.

    Owns the pty master fd and the child. `close()` is idempotent and tears
    down the whole process group: bwrap's --die-with-parent covers us dying,
    but an explicit group kill covers the ordinary case of the client
    disconnecting while the debugger is busy.
    """

    def __init__(self, spec, command):
        self.spec = spec
        master, slave = pty.openpty()
        try:
            # start_new_session gives the child its own process group, so the
            # whole jail can be signalled as a unit on teardown.
            self.proc = subprocess.Popen(
                argv(spec, command),
                stdin=slave, stdout=slave, stderr=slave,
                preexec_fn=_child_setup(spec), start_new_session=True,
            )
        except BaseException:
            os.close(master)
            raise
        finally:
            # The child dup'd the slave; holding our copy open would mean never
            # seeing EOF on the master when the debugger exits.
            os.close(slave)
        self.master_fd = master

    @property
    def pid(self):
        return self.proc.pid

    def set_winsize(self, rows, cols):
        """Propagate the browser terminal's size so gdb wraps output correctly."""
        fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, cols, 0, 0))

    def close(self):
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass
