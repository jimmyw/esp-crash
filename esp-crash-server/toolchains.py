"""Installed debugger toolchains, discovered from build-time jail manifests.

A *toolchain* here is everything the sandbox needs in order to run a debugger
for one target architecture: the gdb binary, the exact shared libraries it
needs, any auxiliary data files (ESP ROM ELFs, an IDF `roms.json`, ...), the
environment those data files are found through, and the name of the converter
that turns a raw uploaded crash artifact into something gdb can open.

Manifests are generated at image build time by `tools/make_jail_manifest.py`
(one `jail-manifest.json` per installed toolchain) rather than being written by
hand, so a base-image change that alters a library closure fails the build
instead of a user's debug session. This module only reads them.

Deliberately vendor-neutral: nothing here knows what Espressif is. An
`arm-none-eabi` or `riscv64-unknown-elf` toolchain is the same kind of entry as
the xtensa one, differing only in its manifest contents. See
`gdb_app/converters/` for the other half of that seam.

Kept as a top-level module (like `decode_module_coredump` and `device_url`)
rather than inside `app/`: it is pure logic with no Flask dependency, and both
the web app and the standalone gdb service import it - putting it in the `app`
package would make the build-time jail smoke test import the whole Flask
application just to read a JSON file.
"""
import functools
import glob
import json
import os
from dataclasses import dataclass, field

# Colon-separated roots to scan. The default covers the historical Espressif
# location plus a vendor-neutral one for non-ESP toolchains, so adding an ARM or
# RISC-V toolchain needs no config change.
DEFAULT_ROOTS = "/opt/esp/tools:/opt/toolchains"

MANIFEST_NAME = "jail-manifest.json"


@dataclass(frozen=True)
class Toolchain:
    """One installed debugger toolchain, as recorded by its jail manifest.

    `libs`/`extra` are absolute host paths that get read-only bound into the
    jail at those same paths (the ELF interpreter and DT_NEEDED lookups use
    standard absolute paths, so remapping them would mean maintaining
    ld.so.conf or RPATH inside the sandbox for no benefit).
    """
    name: str
    arch: str
    version: str
    exe: str
    converter: str
    libs: tuple = ()
    extra: tuple = ()
    env: dict = field(default_factory=dict)

    @property
    def ro_binds(self):
        """Every host path this toolchain needs, read-only, deduplicated and
        ordered so the jail command line is stable (and diffable in tests)."""
        seen = {}
        for p in (self.exe, *self.libs, *self.extra):
            seen[p] = None
        return tuple(seen)


def _load(path):
    with open(path) as f:
        data = json.load(f)
    missing = [k for k in ("name", "arch", "version", "exe", "converter") if not data.get(k)]
    if missing:
        raise ValueError(f"{path}: manifest missing required key(s): {', '.join(missing)}")
    return Toolchain(
        name=data["name"],
        arch=data["arch"],
        version=data["version"],
        exe=data["exe"],
        converter=data["converter"],
        libs=tuple(data.get("libs", ())),
        extra=tuple(data.get("extra", ())),
        env=dict(data.get("env", {})),
    )


def roots():
    return [r for r in os.environ.get("GDB_TOOLCHAIN_ROOTS", DEFAULT_ROOTS).split(":") if r]


def discover():
    """Scan the configured roots for jail manifests. Uncached - use
    `installed()` unless you specifically need a fresh read (tests do)."""
    found = {}
    for root in roots():
        for path in sorted(glob.glob(os.path.join(root, "**", MANIFEST_NAME), recursive=True)):
            tc = _load(path)
            # First root wins, so an override root earlier in the list can
            # shadow a baked-in toolchain of the same name.
            found.setdefault(tc.name, tc)
    return found


@functools.lru_cache(maxsize=1)
def installed():
    """`{name: Toolchain}` for every toolchain in the image. Cached: the set is
    fixed at image build time, and this is read on every session start."""
    return discover()


def get(name):
    """Resolve a toolchain *name* (e.g. a `project_settings.toolchain` value) to
    a Toolchain, or None if it is unset/unknown.

    This is the only place a name coming from the database is turned into
    paths, and it is a dictionary lookup by design - never string
    interpolation - so a hostile value like `../../etc` or an absolute path
    cannot reach the filesystem.
    """
    if not name:
        return None
    return installed().get(name)


def names():
    """Sorted toolchain names, for the project-settings dropdown."""
    return sorted(installed())
