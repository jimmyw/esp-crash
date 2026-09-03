"""Per-session kernel identities, and the work directory that goes with one.

Each live debug session gets its own dedicated uid from a pool of accounts
created at image build time. That is what makes "one session cannot compromise
another" a kernel guarantee rather than a hope: with distinct uids, a
cross-session `ptrace` or `kill` is EPERM even before the pid namespace hides
the target, and `RLIMIT_NPROC` - which is enforced per uid - becomes a real
per-session fork-bomb guard instead of a shared budget one session can exhaust
on everyone else's behalf.

The work directory is deliberately owned `root:<session group>` with mode 0770
rather than being chowned to the session uid. The service runs as root but with
almost every capability dropped, so it holds neither CAP_FOWNER nor
CAP_DAC_OVERRIDE: once a 0700 directory is chowned away, the service can no
longer stat, traverse or remove it, and teardown silently fails. Keeping root as
the owner and granting the session uid access through its group satisfies setup,
the debugger's writes, teardown, and peer exclusion all at once.

Note that a setgid directory would *not* work here, tempting as it looks: the
service runs with almost every capability dropped, so it lacks CAP_FSETID and
the kernel silently strips the setgid bit from the chmod. Files then land in
group root and the jail cannot read them. Ownership is therefore set explicitly
per file - see gdb_app/materialize.py:grant_to_session.
"""
import asyncio
import errno
import os
import pwd
import shutil
import uuid
from dataclasses import dataclass

# Accounts are created as gdbrun0, gdbrun1, ... in the image; the pool is
# whatever exists, so its size is set by the Dockerfile and needs no config.
ACCOUNT_PREFIX = "gdbrun"

DEFAULT_WORK_ROOT = "/run/gdb"


class PoolExhausted(RuntimeError):
    """Every session identity is in use. The caller should turn this into a
    "server busy" response, not a hang or a queue - a debug session is
    interactive, so a client waiting an unbounded time for a slot is worse
    than being told to retry."""


def discover_accounts(prefix=ACCOUNT_PREFIX):
    """The (uid, gid) pairs of the pool accounts present in this image.

    Read from the passwd database rather than computed from a base uid so the
    pool cannot silently drift from what the Dockerfile actually created - a
    mismatch would mean chowning work directories to a nonexistent group.
    """
    out = []
    for entry in pwd.getpwall():
        name = entry.pw_name
        if not name.startswith(prefix):
            continue
        if not name[len(prefix):].isdigit():
            continue
        out.append((entry.pw_uid, entry.pw_gid))
    return sorted(out)


@dataclass(frozen=True)
class Lease:
    """One session's identity and private directory, held for the session's
    lifetime and returned by `SessionPool.release`."""
    session_id: str
    uid: int
    gid: int
    workdir: str


class SessionPool:
    """Hands out session identities and their work directories.

    Bounded by construction: `capacity` is the number of pool accounts, so the
    concurrent-session limit is a property of the image rather than a config
    value that could exceed the number of identities available.
    """

    def __init__(self, work_root=None, accounts=None):
        self.work_root = work_root or os.environ.get("GDB_WORK_ROOT", DEFAULT_WORK_ROOT)
        self._all = list(accounts if accounts is not None else discover_accounts())
        self._free = list(self._all)
        self._lock = asyncio.Lock()

    @property
    def capacity(self):
        return len(self._all)

    @property
    def available(self):
        return len(self._free)

    async def acquire(self):
        async with self._lock:
            if not self._free:
                raise PoolExhausted(
                    f"all {self.capacity} debug session slots are in use")
            uid, gid = self._free.pop(0)
        try:
            return self._make_lease(uid, gid)
        except BaseException:
            # Never lose an identity because directory setup failed.
            async with self._lock:
                self._free.insert(0, (uid, gid))
            raise

    def _make_lease(self, uid, gid):
        session_id = uuid.uuid4().hex
        workdir = os.path.join(self.work_root, session_id)
        os.makedirs(self.work_root, mode=0o711, exist_ok=True)
        # Create it private, then widen to the session's group - never the other
        # way round, and never chown away from root (see the module docstring).
        os.mkdir(workdir, mode=0o700)
        os.chown(workdir, 0, gid)
        os.chmod(workdir, 0o770)
        return Lease(session_id=session_id, uid=uid, gid=gid, workdir=workdir)

    async def release(self, lease):
        """Remove the work directory and return the identity to the pool.

        Runs the (blocking) tree removal off the event loop: a session can
        legitimately have written hundreds of megabytes of core and ELF files,
        and stalling every other session's I/O to delete them is not a
        trade worth making.
        """
        try:
            await asyncio.get_running_loop().run_in_executor(
                None, self._remove, lease.workdir)
        finally:
            async with self._lock:
                if (lease.uid, lease.gid) not in self._free:
                    self._free.append((lease.uid, lease.gid))

    @staticmethod
    def _remove(path):
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            pass
        except OSError as e:
            # Leaving a stale directory behind is bad but recoverable (the work
            # root is a tmpfs and is emptied on restart); refusing to return the
            # identity to the pool would permanently shrink capacity, which is
            # worse. So this is reported by the caller's logs, not raised.
            if e.errno not in (errno.ENOTEMPTY, errno.EACCES, errno.EPERM):
                raise
