#!/usr/bin/env bash
# Build the Espressif Xtensa toolchain package.
#
#   ./xtensa-esp.sh --out /opt/esp-crash-toolchains [--tarball]
#
# Produces one package serving all three Xtensa chips. They differ only in a
# ~400KB core-configuration shared object, so shipping three packages would
# triplicate a 9MB debugger and an 86MB interpreter for nothing; the descriptor
# declares them as `variants` over one payload instead.
#
# Versions are pinned as a set, mirroring the IDF v5.5.4 tools.json manifest.
# Bump them together.
set -euo pipefail

# shellcheck source=common.sh
. "$(dirname "$0")/common.sh"

GDB_VERSION=16.3_20250913
ROM_ELFS_VERSION=20241011
IDF_VERSION=v5.5.4
PY_VERSION=3.12.14
PY_RELEASE=20260901
ESP_COREDUMP_VERSION=1.17.1

PKG_VERSION="$GDB_VERSION"

case "$(uname -m)" in
  x86_64)
    GDB_SHA=16d05c9104ff84529ac3799abb04d5666c193131ab461f153040721728b48730
    GDB_HOST=x86_64-linux-gnu
    PY_SHA=72748da13197c1fb161e3afeef20a6a385ff24f2165e6e2758e47008e7faba4c
    ;;
  aarch64)
    GDB_SHA=ecbd53ba28cf24301be8260249bfcfb60567f938f4402797617c8a0fc170dc7d
    GDB_HOST=aarch64-linux-gnu
    # Not pinned yet: download the aarch64 install_only_stripped asset from the
    # python-build-standalone release, sha256sum it, and put the digest here.
    # Deliberately left empty rather than guessed - fetch_verify must never be
    # handed a checksum nobody verified.
    PY_SHA=
    ;;
  *) die "unsupported build architecture: $(uname -m)" ;;
esac

OUT=
CACHE="${TOOLCHAIN_CACHE:-${TMPDIR:-/tmp}/esp-crash-toolchain-cache}"
WANT_TARBALL=0
FORCE=0

usage() {
  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'USAGE'

Options:
  --out DIR      where to place the package directory (required)
  --tarball      also emit <name>-<version>.tar.gz beside it
  --cache DIR    download cache (default $TMPDIR/esp-crash-toolchain-cache)
  --force        rebuild even if the package directory already exists
USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --out)     OUT="${2:?--out needs a directory}"; shift 2 ;;
    --cache)   CACHE="${2:?--cache needs a directory}"; shift 2 ;;
    --tarball) WANT_TARBALL=1; shift ;;
    --force)   FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

[ -n "$OUT" ] || { usage >&2; die "--out is required"; }
[ -n "$PY_SHA" ] || die "no pinned standalone CPython checksum for $(uname -m) - see the comment above"
need_cmd curl tar sha256sum du

PKG="$OUT/xtensa-esp"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/xtensa-esp-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [ -d "$PKG" ] && [ "$FORCE" != 1 ]; then
  die "$PKG already exists (use --force to rebuild)"
fi
rm -rf "$PKG"
mkdir -p "$PKG"

log "building xtensa-esp $PKG_VERSION -> $PKG"

# --- debugger -----------------------------------------------------------------
# The tarball carries four full gdb builds (~66MB of bin/) plus per-chip Rust
# launchers. Only the no-python build is ever used: the launchers cannot run in
# the sandbox (they resolve themselves through /proc/self/exe, and the jail has
# no /proc), and their sole job - setting XTENSA_GNU_CONFIG - the descriptor
# does directly. So keep one binary, the core configs, and gdb's data directory.
fetch_verify \
  "https://github.com/espressif/binutils-gdb/releases/download/esp-gdb-v${GDB_VERSION}/xtensa-esp-elf-gdb-${GDB_VERSION}-${GDB_HOST}.tar.gz" \
  "$GDB_SHA" "$CACHE/xtensa-esp-elf-gdb-${GDB_VERSION}-${GDB_HOST}.tar.gz"
extract "$CACHE/xtensa-esp-elf-gdb-${GDB_VERSION}-${GDB_HOST}.tar.gz" "$WORK"

SRC="$WORK/xtensa-esp-elf-gdb"
[ -x "$SRC/bin/xtensa-esp-elf-gdb-no-python" ] \
  || die "expected $SRC/bin/xtensa-esp-elf-gdb-no-python in the archive"

mkdir -p "$PKG/gdb/bin"
cp -a "$SRC/bin/xtensa-esp-elf-gdb-no-python" "$PKG/gdb/bin/"
cp -a "$SRC/lib"   "$PKG/gdb/lib"
cp -a "$SRC/share" "$PKG/gdb/share"
log "pruned  gdb to $(du -sh "$PKG/gdb" | cut -f1) (from $(du -sh "$SRC" | cut -f1))"

# --- ROM symbols and the chip->ROM mapping ------------------------------------
fetch_verify \
  "https://github.com/espressif/esp-rom-elfs/releases/download/${ROM_ELFS_VERSION}/esp-rom-elfs-${ROM_ELFS_VERSION}.tar.gz" \
  921f000164a421c7628fbfee55b173384aafaa51883adc65cd27bf9b0af9e9a9 \
  "$CACHE/esp-rom-elfs-${ROM_ELFS_VERSION}.tar.gz"
extract "$CACHE/esp-rom-elfs-${ROM_ELFS_VERSION}.tar.gz" "$PKG/rom-elfs"

# esp-coredump reads this to map a chip revision to a ROM ELF. The Dockerfile
# fetched it with no checksum at all; now it is pinned like everything else.
fetch_verify \
  "https://raw.githubusercontent.com/espressif/esp-idf/${IDF_VERSION}/tools/idf_py_actions/roms.json" \
  86183b0b30e5f96ddec87d0bb657f41879e69312b258fa9cb945ab24adf276cc \
  "$CACHE/roms-${IDF_VERSION}.json"
mkdir -p "$PKG/idf/tools/idf_py_actions"
cp -a "$CACHE/roms-${IDF_VERSION}.json" "$PKG/idf/tools/idf_py_actions/roms.json"

# --- interpreter + esp-coredump ----------------------------------------------
bundle_python "$PY_VERSION" "$PY_RELEASE" "$PY_SHA" "$PKG/python" \
  "esp-coredump==${ESP_COREDUMP_VERSION}"

# --- descriptor ---------------------------------------------------------------
cat > "$PKG/toolchain.yml" <<YML
# Generated by toolchains/recipes/xtensa-esp.sh - regenerate rather than edit.
schema: 1
name: xtensa-esp
arch: xtensa
version: "${GDB_VERSION}"
description: >-
  Espressif Xtensa gdb ${GDB_VERSION} with esp-coredump ${ESP_COREDUMP_VERSION}
  and ROM symbols ${ROM_ELFS_VERSION} (IDF ${IDF_VERSION}).

debugger: gdb/bin/xtensa-esp-elf-gdb-no-python
python: python/bin/python3

env:
  ESP_ROM_ELF_DIR: "{root}/rom-elfs/"
  IDF_PATH: "{root}/idf"

# Outside the package. Resolved in the runtime image and skipped when absent,
# so listing both terminfo locations is correct - Debian puts it in
# /lib/terminfo, most other distributions in /usr/share/terminfo.
#   locale:   without it gdb warns "could not convert ... to UTF-32" on every
#             char array it prints.
#   terminfo: without it readline cannot resolve TERM and falls back to a dumb
#             terminal, losing line editing and history in the browser console.
binds:
  - /usr/lib/locale
  - /lib/terminfo
  - /usr/share/terminfo

requires: [prog]

core:
  timeout: 300
  commands:
    - ["{python}", "-m", "esp_coredump", "info_corefile", "-t", "raw",
       "-c", "{dump}", "--save-core", "{core}", "--gdb", "{debugger}", "{prog}"]

report:
  timeout: 300
  with_symbols: ["--extra-gdbinit-file", "{symbols_file}"]
  commands:
    - ["{python}", "-m", "esp_coredump", "info_corefile", "-t", "raw",
       "-c", "{dump}", "--gdb", "{debugger}", "{prog}"]

interactive:
  with_symbols: ["-x", "{symbols_file}"]
  command: ["{debugger}", "-nx", "-q", "{prog}", "-ex", "core-file {core}"]

modules:
  registry: esp_crash_modmap
  batch: ["{debugger}", "-batch", "-nx", "{prog}", "-ex", "core-file {core}"]
  add_symbols:
    - "add-symbol-file {elf} {text:#x} -s .data {data:#x} -s .bss {bss:#x} -s .rodata {rodata:#x}"

# Xtensa is a configurable architecture: the same binary yields a correct
# backtrace or confident nonsense depending on the core configuration it is
# given, and it reports "xtensa" either way. So the chip is part of the
# toolchain identity, and these ids are what project_settings.toolchain stores.
variants:
  xtensa-esp32:
    chip: esp32
    env: { XTENSA_GNU_CONFIG: "{root}/gdb/lib/xtensa_esp32.so" }
  xtensa-esp32s2:
    chip: esp32s2
    env: { XTENSA_GNU_CONFIG: "{root}/gdb/lib/xtensa_esp32s2.so" }
  xtensa-esp32s3:
    chip: esp32s3
    env: { XTENSA_GNU_CONFIG: "{root}/gdb/lib/xtensa_esp32s3.so" }
YML

finish_package
