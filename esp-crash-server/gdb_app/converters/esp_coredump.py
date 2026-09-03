"""Espressif converter: raw coredump partition image -> core ELF.

Wraps `esp-coredump info_corefile --save-core`, which is the same tool the
existing batch decode path uses (see `decode_module_coredump.save_core`). It is
a Python program that in turn drives gdb, so this converter contributes a whole
Python runtime to the conversion jail's bind list.

That cost is exactly why conversion is a separate, short-lived tier: this is
the code that parses device-supplied bytes, so it runs jailed and under a hard
timeout, and then exits - leaving the long-lived interactive session with only
a static gdb and no Python at all.
"""
import os
import sys
import sysconfig

NAME = "esp_coredump"


def _system_lib_dirs():
    """The system shared-library directories, as whole directories.

    Needed because a Python extension module's dependencies are invisible to
    `ldd` on the interpreter: they are `dlopen`ed at import time. `binascii`
    needs libz, `_ssl` needs libssl/libcrypto, and so on down a long tail that
    changes whenever the base image does. Enumerating that closure by hand
    produces a list that is both large and quietly wrong after the next
    rebuild - the failure mode being an `ImportError` deep inside a conversion.

    So this tier takes the library directories wholesale. That is a real
    widening of the conversion jail and it is the considered trade: conversion
    is batch, timeout-bounded, has no shell and no network, runs under the
    session's own uid in its own namespaces, and already contains a full Python
    interpreter - read-only system libraries add negligible capability on top.
    The tier that is *interactively* driven gets none of this: it runs a single
    static gdb with a five-library closure.
    """
    multiarch = sysconfig.get_config_var("MULTIARCH") or ""
    candidates = ["/lib64", "/usr/lib64"]
    if multiarch:
        candidates += [f"/lib/{multiarch}", f"/usr/lib/{multiarch}"]
    return [p for p in candidates if os.path.isdir(p)]


def extra_ro_binds():
    """Everything `esp-coredump` needs beyond the toolchain's own binds: a
    Python runtime, its packages, and the system libraries its extension
    modules dlopen (see `_system_lib_dirs`)."""
    # Both the symlink names and the real binary: `sys.executable` is usually
    # /usr/local/bin/python -> python3 -> python3.12, and code inside the jail
    # may resolve any of those names.
    paths = {sys.executable, os.path.realpath(sys.executable)}
    for name in ("python", "python3"):
        cand = os.path.join(os.path.dirname(sys.executable), name)
        if os.path.exists(cand):
            paths.add(cand)
    for key in ("stdlib", "purelib", "platlib"):
        p = sysconfig.get_paths().get(key)
        if p and os.path.isdir(p):
            paths.add(os.path.realpath(p))
    # libpython and the interpreter's own closure. ldd reports libpython via a
    # relative path (`/usr/local/bin/../lib/...`), hence the realpath.
    libdir = sysconfig.get_config_var("LIBDIR")
    ldlib = sysconfig.get_config_var("LDLIBRARY")
    if libdir and ldlib:
        cand = os.path.realpath(os.path.join(libdir, ldlib))
        if os.path.exists(cand):
            paths.add(cand)
    paths.update(_system_lib_dirs())
    return tuple(sorted(paths))


def convert(run, toolchain, dump, prog, out, *, work=None):
    """Convert `dump` to the core ELF `out`, returning esp-coredump's own
    panic/backtrace text.

    Invoked as `python -m esp_coredump` rather than through the `esp-coredump`
    console script: the script's shebang hardcodes an interpreter path, and
    inside the jail the module form has one less thing to get wrong.
    """
    result = run([
        os.path.realpath(sys.executable), "-m", "esp_coredump",
        "info_corefile",
        "-t", "raw",
        "-c", dump,
        "--save-core", out,
        "--gdb", toolchain.exe,
        prog,
    ])
    return (result.stdout or b"").decode("utf-8", "replace")
