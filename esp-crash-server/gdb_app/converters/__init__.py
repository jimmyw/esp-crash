"""Converters: raw uploaded crash artifact -> something gdb can open.

This is the seam that keeps the debugger service vendor-neutral. An ESP crash
arrives as a raw coredump *partition image* that only `esp-coredump` knows how
to interpret; other targets (ARM, RISC-V) will upload a real ELF core that gdb
opens directly, or a proprietary format needing its own parser. Rather than
branching on chip family in the session code, each toolchain's manifest names
the converter to use, and each converter is a module here exposing the same two
functions:

    extra_ro_binds() -> tuple[str, ...]
        Host paths this converter needs bound into the conversion jail, beyond
        the toolchain's own. This is why the interactive session tier can stay
        tiny (one static gdb, a five-library closure) while conversion is
        allowed to drag in a whole Python runtime: they are different jails.

    convert(run, toolchain, dump, prog, out) -> str
        Produce `out` from `dump`, returning human-readable log text. Paths are
        jail-relative (under /work). `run(command, timeout=...)` executes a
        command inside the conversion jail.

Converters run on attacker-influenced bytes, so they are always invoked in the
short-lived, timeout-bounded conversion tier - never in the process that holds
the interactive pty, and never in this service's own process.
"""
import importlib

# Explicit allow-list: a converter name comes from a toolchain manifest, and
# resolving it must not be able to import arbitrary modules.
KNOWN = ("esp_coredump", "passthrough")


class UnknownConverter(LookupError):
    pass


def get(name):
    if name not in KNOWN:
        raise UnknownConverter(
            f"unknown converter {name!r}; known: {', '.join(KNOWN)}")
    return importlib.import_module(f"{__name__}.{name}")
