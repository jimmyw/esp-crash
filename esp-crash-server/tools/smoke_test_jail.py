#!/usr/bin/env python3
"""Build-time validation of every installed toolchain's jail manifest.

Run from the Dockerfile, immediately after the manifests are generated. Its
purpose is failure timing: a manifest that does not match the image produces a
sandbox where the debugger dies with "error while loading shared libraries",
and this turns that into a failed image build rather than a failed debug
session in front of a user months later.

One check cannot run here. bubblewrap needs to create a user namespace, and
`docker build` runs under Docker's default seccomp profile, which blocks
`clone`/`unshare` with CLONE_NEWUSER - so entering a real jail is impossible at
build time (see the `security_opt` on the esp-crash-gdb service, which is what
makes it possible at run time). Rather than pretend otherwise, that step is
attempted and reported as skipped when the environment forbids it; the
end-to-end jail check lives in the `integration`-marked tests, which run in a
properly configured container. Everything that *can* be checked without
namespaces is checked unconditionally:

  * every path the manifest records still exists in the image;
  * the debugger's current ldd closure is covered by the manifest, so a
    manifest generated earlier in the build cannot go stale silently;
  * the debugger binary actually executes and identifies itself;
  * the converter the manifest names resolves, and its own binds exist;
  * bubblewrap is installed and runnable.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import toolchains                                    # noqa: E402
from gdb_app import converters, jail                 # noqa: E402
from tools.make_jail_manifest import ldd_closure     # noqa: E402

# bwrap's message when the kernel or a seccomp filter forbids the user
# namespace. Matched so a genuine sandbox failure is still reported as one.
_NO_USERNS = "No permissions to create new namespace"


class Failure(Exception):
    pass


def _check_paths_exist(tc):
    missing = [p for p in tc.ro_binds if not os.path.exists(p)]
    if missing:
        raise Failure(f"manifest references missing path(s): {', '.join(missing)}")


def _check_closure_covered(tc):
    """The manifest must still cover what the binary actually needs now."""
    current = set(ldd_closure(tc.exe))
    uncovered = sorted(current - set(tc.libs))
    if uncovered:
        raise Failure(
            "manifest is stale - these libraries are needed but not recorded: "
            + ", ".join(uncovered))


def _check_runs(tc):
    proc = subprocess.run([tc.exe, "--version"], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=60)
    out = (proc.stdout or b"").decode("utf-8", "replace")
    if proc.returncode != 0 or "GNU gdb" not in out:
        raise Failure(f"{tc.exe} did not run: exit {proc.returncode}: {out[:200]}")
    return out.splitlines()[0].strip()


def _check_converter(tc):
    try:
        conv = converters.get(tc.converter)
    except converters.UnknownConverter as e:
        raise Failure(str(e)) from None
    missing = [p for p in conv.extra_ro_binds() if not os.path.exists(p)]
    if missing:
        raise Failure(
            f"converter {tc.converter} needs missing path(s): {', '.join(missing)}")


def _try_jail(tc, workdir):
    """Attempt a real jailed run. Returns 'ok', or 'skipped: ...'."""
    spec = jail.JailSpec(toolchain=tc, workdir=workdir,
                         uid=os.getuid(), gid=os.getgid(), tier=jail.SESSION)
    result = jail.run_batch(spec, [tc.exe, "--version"], timeout=60)
    out = (result.stdout or b"").decode("utf-8", "replace")
    if result.returncode == 0 and "GNU gdb" in out:
        return "ok"
    if _NO_USERNS in out:
        return "skipped (no user namespaces in this environment)"
    raise Failure(f"jailed run failed: exit {result.returncode}: {out[:300]}")


def main():
    if not (bwrap := jail.BWRAP) or not os.path.exists(bwrap):
        raise SystemExit(f"bubblewrap not found at {jail.BWRAP} - the debug "
                         f"sandbox cannot be built without it")

    found = toolchains.discover()
    if not found:
        raise SystemExit(
            "no jail manifests found under "
            f"{':'.join(toolchains.roots())} - did make_jail_manifest.py run?")

    workdir = "/tmp/jail-smoke"
    os.makedirs(workdir, exist_ok=True)

    failures = 0
    for name, tc in sorted(found.items()):
        try:
            _check_paths_exist(tc)
            _check_closure_covered(tc)
            version = _check_runs(tc)
            _check_converter(tc)
            jailed = _try_jail(tc, workdir)
        except Failure as e:
            print(f"FAIL  {name}: {e}")
            failures += 1
            continue
        print(f"ok    {name} ({tc.arch}, {len(tc.libs)} libs, "
              f"converter={tc.converter}): {version}; jailed run: {jailed}")

    if failures:
        raise SystemExit(f"{failures} toolchain manifest(s) failed validation")
    print(f"all {len(found)} toolchain manifest(s) validated")


if __name__ == "__main__":
    main()
