"""Fingerprint a symbolicated crash dump for duplicate grouping, without
calling an LLM. Addresses, register values, and call-argument values (all
pointer/runtime state) differ between devices and even between two crashes
from the *same* bug, so they can't be part of a duplicate signature. What's
stable for "this is the same bug" is the ordered sequence of function names
in the GDB backtrace (esp-coredump's `CURRENT THREAD STACK` section when
the report has one, otherwise the first backtrace block) - confirmed against
real crash dumps in this project (e.g. the ota_manifest watchdog case: two
different devices, identical function-name sequence, differing only in
addresses/timer handles).

The outermost few frames (panic_abort/esp_system_abort/abort/the FreeRTOS
task wrapper) are dropped before hashing - they're present on every crash
regardless of cause and would otherwise dominate a short signature.
"""
import hashlib
import re

_STACK_HEADER = "CURRENT THREAD STACK"
_SECTION_RULE = re.compile(r'^=+ .+ =+$')
_FRAME_RE = re.compile(r'^#\d+\s+(?:0x[0-9a-fA-F]+\s+in\s+)?([A-Za-z_]\w*)\s*\(')
_FRAME_INDEX_RE = re.compile(r'^#(\d+)\s')
_GENERIC_FRAMES = {"panic_abort", "esp_system_abort", "abort", "vPortTaskWrapper"}
_FRAME_COUNT = 6


def _plain_backtrace_frames(lines):
    """Frames from a plain GDB backtrace, for toolchains whose report carries
    no esp-coredump section headers - any report built from
    `-ex "thread apply all bt full"`, which is what the vendor-neutral
    descriptors (arm-none-eabi among them) produce.

    Only the first backtrace block counts. GDB prints the current frame when it
    opens the core and then prints it again under `Thread N (...)`, and a
    multi-threaded report lists every thread after that; keeping the first
    block yields the crashing thread's stack, which is exactly what the
    esp-coredump path's CURRENT THREAD STACK section gives.
    """
    frames = []
    for line in lines:
        stripped = line.strip()
        match = _FRAME_RE.match(stripped)
        if not match:
            continue
        index = _FRAME_INDEX_RE.match(stripped)
        if frames and index and index.group(1) == "0":
            break               # a second backtrace block has started
        frames.append(match.group(1))
    return frames


def _stack_frames(dump):
    lines = dump.splitlines()
    start = next((i for i, line in enumerate(lines) if _STACK_HEADER in line), None)
    if start is None:
        # No esp-coredump header. Falling back rather than giving up is what
        # lets a non-Espressif toolchain's crashes be grouped at all; a dump
        # that has the header keeps its existing signature untouched, so no
        # stored signature changes because of this.
        return _plain_backtrace_frames(lines)
    frames = []
    for line in lines[start + 1:]:
        stripped = line.strip()
        if _SECTION_RULE.match(stripped):
            break
        m = _FRAME_RE.match(stripped)
        if m:
            frames.append(m.group(1))
    return frames


def compute_signature(dump):
    """Hex signature grouping crashes with the same root cause, or None if
    `dump` has no parseable GDB backtrace (e.g. a decode failure message)."""
    if not dump:
        return None
    frames = [f for f in _stack_frames(dump) if f not in _GENERIC_FRAMES][:_FRAME_COUNT]
    if not frames:
        return None
    return hashlib.sha256("|".join(frames).encode()).hexdigest()
