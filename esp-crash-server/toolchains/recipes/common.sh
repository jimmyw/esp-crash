# Shared helpers for building toolchain packages.
#
# A toolchain package is a self-contained directory: a debugger, whatever data
# files it needs, optionally its own interpreter, and a `toolchain.yml`
# describing how to drive it. The server mounts the directory read-only and
# reads the descriptor at runtime, so these scripts are the *only* place that
# downloads anything - the image does not.
#
# Sourced, not executed. Callers must `set -euo pipefail` themselves.

# Every download is checksum-verified. These archives end up executing inside
# the debug sandbox, so an unverified fetch would be the weakest link in the
# whole design - which is why there is no unchecked-download helper here at all.
fetch_verify() {
  # `local` throughout: these helpers call each other, and an unscoped `dest`
  # in the callee silently clobbers the caller's.
  local url="$1" sha256="$2" dest="$3"

  if [ -f "$dest" ] && printf '%s  %s\n' "$sha256" "$dest" | sha256sum -c - >/dev/null 2>&1; then
    log "cached  $(basename "$dest")"
    return 0
  fi

  log "fetch   $(basename "$dest")"
  mkdir -p "$(dirname "$dest")"
  # --location: GitHub release assets redirect. Note that a '+' in an asset
  # name must already be percent-encoded as %2B by the caller; curl will not do
  # it and the raw '+' yields a 404.
  curl -fsSL --retry 3 --retry-delay 2 -o "$dest.part" "$url"
  printf '%s  %s\n' "$sha256" "$dest.part" | sha256sum -c - >/dev/null \
    || die "checksum mismatch for $url
  expected $sha256
  got      $(sha256sum "$dest.part" | cut -d' ' -f1)"
  mv "$dest.part" "$dest"
}

extract() {
  local archive="$1" dest="$2" strip="${3:-0}"
  log "unpack  $(basename "$archive") -> ${dest#"$PKG"/}"
  mkdir -p "$dest"
  tar xzf "$archive" -C "$dest" --strip-components="$strip"
}

# Bundle a relocatable CPython and pip-install into it. Used by any toolchain
# whose report step needs an interpreter; the point is that the *package* owns
# it, so the server image needs no per-vendor Python packages and cannot drift
# out of step with one.
bundle_python() {
  local version="$1" release="$2" sha256="$3" dest="$4"
  shift 4
  local arch triple asset encoded

  arch="$(uname -m)"
  case "$arch" in
    x86_64)  triple=x86_64-unknown-linux-gnu ;;
    aarch64) triple=aarch64-unknown-linux-gnu ;;
    *) die "no pinned standalone CPython for $arch" ;;
  esac

  # The stripped build is 32MB against 106MB and still ships pip and a working
  # libpython; nothing here needs debug symbols for the interpreter itself.
  asset="cpython-${version}+${release}-${triple}-install_only_stripped.tar.gz"
  encoded="$(printf '%s' "$asset" | sed 's/+/%2B/')"

  fetch_verify \
    "https://github.com/astral-sh/python-build-standalone/releases/download/${release}/${encoded}" \
    "$sha256" "$CACHE/$asset"

  # The archive contains a top-level `python/`, which lands as $dest.
  extract "$CACHE/$asset" "$(dirname "$dest")"

  if [ "$#" -gt 0 ]; then
    log "pip     $*"
    "$dest/bin/python3" -m pip install --quiet --root-user-action=ignore \
      --no-cache-dir --no-warn-script-location "$@" \
      || die "pip install failed in the bundled interpreter"
  fi

  prune_python "$dest"
}

# Strip an interpreter down to what a headless post-mortem sandbox can use.
#
# This is not only about size. A GUI toolkit, a code-refactoring library and a
# package installer have no business inside a jail that exists to read a core
# dump, and `verify.py` rightly complains about `_tkinter.so` referencing Tcl
# libraries through an unresolvable RPATH. Removing them is the honest fix.
prune_python() {
  local dest="$1" before after

  before="$(du -sm "$dest" | cut -f1)"

  # pip and ensurepip are build-time only - the sandbox installs nothing, ever.
  rm -rf "$dest"/lib/python*/site-packages/pip          "$dest"/lib/python*/site-packages/pip-*.dist-info          "$dest"/lib/python*/ensurepip          "$dest"/bin/pip* 2>/dev/null || true

  # Tcl/Tk and tkinter: a windowing toolkit in a headless jail.
  rm -rf "$dest"/lib/libtcl* "$dest"/lib/libtk*          "$dest"/lib/tcl* "$dest"/lib/tk*          "$dest"/lib/thread[0-9]* "$dest"/lib/itcl[0-9]*          "$dest"/lib/python*/tkinter          "$dest"/lib/python*/lib-dynload/_tkinter*.so 2>/dev/null || true

  # Developer conveniences with no runtime role here.
  rm -rf "$dest"/lib/python*/idlelib "$dest"/lib/python*/lib2to3          "$dest"/lib/python*/pydoc_data "$dest"/lib/python*/test          "$dest"/lib/python*/config-* 2>/dev/null || true

  find "$dest" -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find "$dest" -name '*.a' -delete 2>/dev/null || true

  # These builds link libpython into the executable *and* ship the shared
  # object for embedders - 31MB of it. Drop it only when nothing needs it,
  # checked rather than assumed: being wrong means the interpreter stops
  # starting, and only inside the sandbox.
  local interp
  interp="$(ls "$dest"/bin/python3.[0-9]* 2>/dev/null | head -1)"
  if [ -n "$interp" ] && ! ldd "$interp" 2>/dev/null | grep -q libpython; then
    # Extension modules on Linux never link libpython either, so if the
    # interpreter does not, nothing in the tree does.
    rm -f "$dest"/lib/libpython*.so "$dest"/lib/libpython*.so.[0-9]*
    log "pruned  libpython shared object (statically linked into the binary)"
  fi

  # Prove the result still works before anyone ships it.
  "$dest/bin/python3" -c 'import zlib, ssl, hashlib, ctypes, binascii, lzma'     || die "pruning broke the bundled interpreter's standard library"

  after="$(du -sm "$dest" | cut -f1)"
  log "pruned  interpreter ${before}M -> ${after}M"
}

# Verify the finished package, then optionally tar it for another machine.
finish_package() {
  local out
  "$(dirname "$0")/verify.py" "$PKG" || die "package verification failed"

  log "size    $(du -sh "$PKG" | cut -f1)"
  if [ "${WANT_TARBALL:-0}" = 1 ]; then
    out="$(dirname "$PKG")/$(basename "$PKG")-${PKG_VERSION}.tar.gz"
    log "tarball $out"
    tar czf "$out" -C "$(dirname "$PKG")" "$(basename "$PKG")"
  fi
  log "done    $PKG"
}

log() { printf '  %s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

need_cmd() {
  local c
  for c in "$@"; do
    command -v "$c" >/dev/null 2>&1 || die "required command not found: $c"
  done
}
