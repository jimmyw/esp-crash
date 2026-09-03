"""Batch-decode logic: toolchain resolution and the error taxonomy.

Pure logic, no Docker and no database. The endpoint's HTTP surface is covered
in tests/test_decode_endpoint.py, which needs Postgres.

The toolchain fallback is the reason this file exists. `project_settings.toolchain`
is set on a minority of projects, and the previous in-process decode never
consulted it at all - it picked a debugger off PATH for every project. So
refusing to decode when the column is NULL would have silently stopped
pre-analysis for most projects, and these tests pin the fallback that prevents
that.
"""
import pytest

import toolchains
from gdb_app import decode


class FakeToolchain:
    def __init__(self, name, requires=("prog",)):
        self.name = name
        self.requires = requires


@pytest.fixture
def installed(monkeypatch):
    def _install(*names):
        entries = {n: FakeToolchain(n) for n in names}
        monkeypatch.setattr(toolchains, "installed", lambda: entries)
        return entries
    return _install


# ------------------------------------------------------- toolchain resolution

def test_a_configured_toolchain_is_used(installed):
    installed("xtensa-esp32")
    tc, source = decode.resolve_toolchain("xtensa-esp32")
    assert tc.name == "xtensa-esp32" and source == "project"


def test_an_unset_toolchain_falls_back_to_the_server_default(installed, monkeypatch):
    installed("xtensa-esp32")
    monkeypatch.setenv(decode.DEFAULT_TOOLCHAIN_ENV, "xtensa-esp32")
    tc, source = decode.resolve_toolchain(None)
    assert tc.name == "xtensa-esp32" and source == "default"


def test_the_fallback_is_visible_in_the_source_field(installed, monkeypatch):
    """Callers need to tell which crashes relied on the default: a project that
    later sets its own toolchain may produce different reports, and therefore
    a different signature and a re-bucketed crash."""
    installed("a", "b")
    monkeypatch.setenv(decode.DEFAULT_TOOLCHAIN_ENV, "b")
    assert decode.resolve_toolchain("a")[1] == "project"
    assert decode.resolve_toolchain(None)[1] == "default"


def test_an_unset_toolchain_with_no_default_is_retryable(installed, monkeypatch):
    """Retryable, emphatically: treating this as permanent would write an error
    message into the dump column of every crash in every unconfigured
    project."""
    installed("xtensa-esp32")
    monkeypatch.delenv(decode.DEFAULT_TOOLCHAIN_ENV, raising=False)
    with pytest.raises(decode.DecodeError) as e:
        decode.resolve_toolchain(None)
    assert e.value.code == "no_toolchain" and e.value.retryable is True


def test_a_configured_but_uninstalled_toolchain_is_retryable(installed):
    """The name may be a typo, or a package may simply not be mounted yet -
    both are conditions an operator can fix, so the crash must not be marked
    as permanently undecodable."""
    installed("xtensa-esp32")
    with pytest.raises(decode.DecodeError) as e:
        decode.resolve_toolchain("xtensa-esp32s9")
    assert e.value.code == "no_toolchain" and e.value.retryable is True
    assert "not installed" in e.value.message
    assert "xtensa-esp32" in e.value.message, "should say what is available"


def test_a_default_naming_something_uninstalled_is_refused(installed, monkeypatch):
    installed("xtensa-esp32")
    monkeypatch.setenv(decode.DEFAULT_TOOLCHAIN_ENV, "does-not-exist")
    with pytest.raises(decode.DecodeError) as e:
        decode.resolve_toolchain(None)
    assert e.value.code == "no_toolchain"


# ---------------------------------------------------------- the error taxonomy

@pytest.mark.parametrize("code,retryable", [
    # Permanent: the stored artifact will not decode however often it is tried,
    # so the message is stored as the dump and the crash stops being requeued.
    ("no_dump", False),
    ("convert_failed", False),
    # Transient: something an operator or a later upload can change.
    ("no_build", True),
    ("no_toolchain", True),
    ("busy", True),
])
def test_error_retryability_matches_whether_a_retry_could_help(code, retryable):
    e = decode.DecodeError(code, "why", retryable=retryable)
    assert e.as_dict()["error"] == {"code": code, "message": "why",
                                    "retryable": retryable}


def test_a_busy_pool_is_a_503(installed):
    e = decode.DecodeError("busy", "full", retryable=True, status=503)
    assert e.status == 503


def test_not_found_is_permanent():
    e = decode.DecodeError("not_found", "gone", retryable=False, status=404)
    assert e.status == 404 and e.retryable is False
