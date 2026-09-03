"""No-op converter: the uploaded artifact is already a core file gdb can open.

The expected shape for targets that dump a real ELF core rather than a
vendor-specific partition image. Costs nothing and needs no extra binds, which
is the point - a target using this never pulls a Python runtime into any jail.
"""
import os
import shutil

NAME = "passthrough"


def extra_ro_binds():
    return ()


def convert(run, toolchain, dump, prog, out, *, work=None):
    """Present `dump` as `out`. `run` is unused: there is nothing to execute,
    so no jail is entered at all for this conversion."""
    if work is None:
        raise ValueError("passthrough converter needs the host work directory")
    src, dst = os.path.join(work, dump), os.path.join(work, out)
    if src != dst:
        shutil.copyfile(src, dst)
    return "# artifact used directly as a core file (no conversion needed)\n"
