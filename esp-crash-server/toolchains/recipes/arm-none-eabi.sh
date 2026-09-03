#!/usr/bin/env bash
# Build the GNU Arm Embedded toolchain package, for EFR32 (and any other ARM
# target whose crash artifact is already an ELF core dump).
#
#   ./arm-none-eabi.sh --out /opt/esp-crash-toolchains [--tarball]
#
# Almost all of this package is *absence*, which is the point - the descriptor
# format should not need ESP-shaped machinery for a target that has none:
#   no `core:`    the uploaded artifact already IS an ET_CORE ELF
#   no `modules:` this target has no runtime module registry
#   no `python:`  nothing here needs an interpreter
#
# gdb version matters here, and not for the usual reasons. Reading a *bare
# metal* ARM core needs gdb's `arm-none-tdep` support, which arrived in gdb 11:
# without it gdb rejects the file outright with "Core file format not
# supported", because a bare-metal build has no GNU/Linux OSABI handler to
# interpret NT_PRSTATUS. Measured on a real EFR32 core: Silicon Labs'
# Simplicity Studio drop (gdb 10.1.90, OSABI list "auto, default, none,
# PikeOS") cannot read it at all, while this build produces a fully
# symbolicated backtrace with locals. So do not swap this for an older vendor
# toolchain, however convenient it is to have one on disk already.
set -euo pipefail

# shellcheck source=common.sh
. "$(dirname "$0")/common.sh"

XPACK_VERSION=15.2.1-1.1
GDB_VERSION=16.3.90.20250906
PKG_VERSION="$XPACK_VERSION"

case "$(uname -m)" in
  x86_64)
    XPACK_HOST=linux-x64
    XPACK_SHA=da6a49ad4003944b823c6c93702a8787c922ab34bd7e918ec0eaf6933a9b1ff6
    ;;
  aarch64)
    XPACK_HOST=linux-arm64
    # Not pinned: download the linux-arm64 asset from the same xPack release,
    # sha256sum it, and put the digest here. Deliberately left empty rather
    # than guessed - fetch_verify must never be handed an unverified checksum.
    XPACK_SHA=
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

[ -n "$OUT" ]      || { usage >&2; die "--out is required"; }
[ -n "$XPACK_SHA" ] || die "no pinned xPack checksum for $(uname -m) - see the comment above"
need_cmd curl tar sha256sum du

PKG="$OUT/arm-none-eabi"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/arm-none-eabi-build.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if [ -d "$PKG" ] && [ "$FORCE" != 1 ]; then
  die "$PKG already exists (use --force to rebuild)"
fi
rm -rf "$PKG"
mkdir -p "$PKG"

log "building arm-none-eabi $PKG_VERSION (gdb $GDB_VERSION) -> $PKG"

# --- debugger -----------------------------------------------------------------
# One binary and its libraries out of a 293MB compiler suite. The `-py3` build
# is skipped for the same reason as Espressif's `-no-python`: a gdb embedding
# CPython needs its interpreter and script directory inside the jail to start
# at all, and nothing here needs pretty-printers to read a core dump.
ASSET="xpack-arm-none-eabi-gcc-${XPACK_VERSION}-${XPACK_HOST}.tar.gz"
fetch_verify \
  "https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack/releases/download/v${XPACK_VERSION}/${ASSET}" \
  "$XPACK_SHA" "$CACHE/$ASSET"

SRC_TOP="xpack-arm-none-eabi-gcc-${XPACK_VERSION}"
# `libexec/*.so*` rather than all of libexec: that directory also holds the
# compiler backends (cc1, cc1plus, lto1 - ~100MB), which a package that only
# ever reads core dumps has no use for.
log "unpack  $ASSET (debugger, its libraries, and gdb's data directory)"
tar xzf "$CACHE/$ASSET" -C "$WORK" --wildcards \
  "$SRC_TOP/bin/arm-none-eabi-gdb" \
  "$SRC_TOP/libexec/*.so*" \
  "$SRC_TOP/arm-none-eabi/share/gdb"

SRC="$WORK/$SRC_TOP"
[ -x "$SRC/bin/arm-none-eabi-gdb" ] || die "expected $SRC_TOP/bin/arm-none-eabi-gdb in the archive"

# The relative layout is load-bearing and must be preserved exactly:
#   bin/arm-none-eabi-gdb has RPATH $ORIGIN/../libexec, which is how its
#   bundled libraries resolve with no LD_LIBRARY_PATH and no ld.so.cache - and
#   the jail has neither.
#   gdb then resolves its data directory relocatably to
#   <bindir>/../arm-none-eabi/share/gdb, hence the doubled directory name.
# Both work unchanged inside the jail because the package is bound at the same
# path it occupies on the host.
mkdir -p "$PKG/bin" "$PKG/libexec" "$PKG/arm-none-eabi/share"
cp -a "$SRC/bin/arm-none-eabi-gdb"      "$PKG/bin/"
cp -a "$SRC"/libexec/*.so*              "$PKG/libexec/"
cp -a "$SRC/arm-none-eabi/share/gdb"    "$PKG/arm-none-eabi/share/gdb"

# --- descriptor ---------------------------------------------------------------
cat > "$PKG/toolchain.yml" <<YML
# Generated by toolchains/recipes/arm-none-eabi.sh - regenerate rather than edit.
schema: 1
name: arm-none-eabi
arch: arm
version: "${XPACK_VERSION}"
description: >-
  GNU Arm Embedded gdb ${GDB_VERSION} (xPack ${XPACK_VERSION}), for targets
  whose crash artifact is already an ELF core dump - EFR32 among them.

debugger: bin/arm-none-eabi-gdb

# The debugger's own libraries, shipped with it. Its RPATH (\$ORIGIN/../libexec)
# already finds them, but the package is bound into the jail as a single
# directory, so nothing inside it can be discovered from the bind list -
# declaring the directory keeps this working for a future build without an
# RPATH, and makes the package's copies win over any the host happens to have.
library_path: ["{root}/libexec"]

# Outside the package. Resolved in the runtime image and skipped when absent,
# so listing both terminfo locations is correct - Debian puts it in
# /lib/terminfo, most other distributions in /usr/share/terminfo.
binds:
  - /usr/lib/locale
  - /lib/terminfo
  - /usr/share/terminfo

requires: [prog]

# No 'core' phase: the artifact is already an ET_CORE ELF, so the service
# copies it and the debugger opens it directly.

report:
  timeout: 120
  commands:
    - ["{debugger}", "-batch", "-nx", "{prog}", "-ex", "core-file {core}",
       "-ex", "thread apply all bt full", "-ex", "info registers"]

interactive:
  command: ["{debugger}", "-nx", "-q", "{prog}", "-ex", "core-file {core}"]
YML

finish_package
