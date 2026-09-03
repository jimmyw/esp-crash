"""Checks on the debug console template's external dependencies.

These exist because of a real failure: the page referenced
`cdnjs.../xterm/5.3.0/xterm.min.js` and an `xterm-addon-fit` library that does
not exist on that CDN at all. Both 404'd, `Terminal` and `FitAddon` were
undefined, the first use threw, and the whole script aborted - leaving a black
box reading "connecting..." with nothing to indicate why. The page looked
broken in exactly the same way a server-side fault would look.

So: the URLs must stay pinned and reachable, and the page must say something
when they are not.
"""
import re

import pytest

TEMPLATE = "templates/gdb.html"

CDN_URL = re.compile(r'(?:src|href)="(https://[^"]+)"')


@pytest.fixture(scope="module")
def page():
    with open(TEMPLATE) as f:
        return f.read()


@pytest.fixture(scope="module")
def urls(page):
    found = CDN_URL.findall(page)
    assert found, "no external assets found - has the template changed shape?"
    return found


def test_external_assets_are_version_pinned(urls):
    for url in urls:
        assert "@latest" not in url and "/latest/" not in url, \
            f"{url} is unpinned; a major release would change the page silently"
        assert re.search(r"@\d+\.\d+\.\d+|/\d+\.\d+\.\d+/", url), \
            f"{url} carries no explicit version"


def test_the_page_reports_a_missing_terminal_library(page):
    # The guard that turns a CDN failure into a message instead of a blank box.
    assert 'typeof Terminal === "undefined"' in page
    assert "could not be loaded" in page


def test_the_fit_addon_is_optional(page):
    """A failure to load the sizing addon must cost the terminal its exact
    dimensions, not the whole session."""
    assert 'typeof FitAddon !== "undefined"' in page
    assert "if (fit) { fit.fit(); }" in page


def test_the_page_embeds_no_crash_data_or_ticket(page):
    # Everything shown arrives over the WebSocket; a ticket rendered into HTML
    # would sit in the browser history.
    assert "{{ dump" not in page
    assert "ticket=" not in page


@pytest.mark.integration
def test_every_external_asset_actually_resolves(urls):
    """The check that would have caught the original bug. Needs network, so it
    is integration-marked like the toolchain tests."""
    import urllib.error
    import urllib.request

    failures = []
    for url in urls:
        try:
            request = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(request, timeout=20) as response:
                if response.status != 200:
                    failures.append(f"{url} -> HTTP {response.status}")
        except urllib.error.HTTPError as e:
            failures.append(f"{url} -> HTTP {e.code}")
        except Exception as e:                              # noqa: BLE001
            pytest.skip(f"no network access for this check: {e}")
    assert not failures, "unreachable assets:\n" + "\n".join(failures)
