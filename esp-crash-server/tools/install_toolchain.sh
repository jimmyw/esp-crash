#!/bin/sh
# Download, verify and unpack one debugger toolchain.
#
# Factored out of the Dockerfile so that adding a toolchain for a new chip
# family (riscv32-esp-elf, arm-none-eabi, ...) is one more invocation rather
# than another copy of the download-and-verify boilerplate. The checksum is
# mandatory: these tarballs are fetched over the network at build time and are
# the thing that ends up executing inside the debug sandbox.
#
# Usage: install_toolchain.sh <url> <sha256> <dest-dir>
set -eu

url="$1"
sha256="$2"
dest="$3"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

curl -fsSL "$url" -o "$tmp"
echo "${sha256}  ${tmp}" | sha256sum -c -
mkdir -p "$dest"
tar xzf "$tmp" -C "$dest"
