"""Checks on the debug console template's external dependencies.

These exist because of a real failure: the page referenced
`cdnjs.../xterm/5.3.0/xterm.min.js` and an `xterm-addon-fit` library that does
not exist on that CDN at all. Both 404'd, `Terminal` and `FitAddon` were
undefined, the first use threw, and the whole script aborted - leaving a black
box reading "connecting..." with nothing to indicate why. The page looked
broken in exactly the same way a server-side fault would look.

So: the URLs must stay pinned and reachable, and the page must say something
when they are not.

Also covers what reaches the terminal, for a related reason. A terminal needs a
carriage return to return to column zero - a bare newline only moves down - so
any text written there from outside the pty must be normalised. The converter's
multi-line panic report was going out through a JSON status frame and being
written raw, staircasing the whole thing. Byte-stream tests missed it because
Python's splitlines() treats "\n" and "\r\n" alike; only a real terminal shows
the difference.
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


# ------------------------------------------------- what reaches the terminal

def test_to_crlf_normalises_bare_newlines():
    from gdb_app.server import to_crlf
    assert to_crlf("one\ntwo\nthree") == "one\r\ntwo\r\nthree"


def test_to_crlf_leaves_existing_crlf_alone():
    """Must be idempotent: gdb's own output already arrives as CRLF via the
    pty's ONLCR, and doubling the carriage returns would be its own bug."""
    from gdb_app.server import to_crlf
    assert to_crlf("one\r\ntwo") == "one\r\ntwo"
    assert to_crlf(to_crlf("one\ntwo")) == "one\r\ntwo"


def test_to_crlf_handles_empty_and_trailing_newlines():
    from gdb_app.server import to_crlf
    assert to_crlf("") == ""
    assert to_crlf("\n") == "\r\n"
    assert to_crlf("a\n\nb") == "a\r\n\r\nb"


def test_the_page_writes_multi_line_messages_line_by_line(page):
    """Status and error messages can be multi-line - a refused session appends
    the converter log to its explanation - so the client must not assume one
    line per message."""
    assert "function writeLines" in page
    assert "split(/\\r?\\n/)" in page
    # ...and nothing may write a raw message straight to the terminal.
    assert "term.writeln('\\x1b[90m' + msg.message" not in page


def test_the_scrollbar_gutter_is_enforced_from_the_dom(page):
    """xterm sizes .xterm-screen to the renderer's canvas width and paints it
    over .xterm-viewport, so a screen as wide as the viewport buries the
    scrollbar. Measured on the live page: both 1119px, gutter 0, with 6075px
    of scrollback behind a bar that could not be seen or dragged. The fit
    addon's own scrollbar reservation did not produce a gutter, so the page
    must measure the two elements and trim columns itself."""
    assert "function fitTerminal" in page
    assert ".xterm-viewport" in page and ".xterm-screen" in page
    assert "viewport.offsetWidth - screen.offsetWidth" in page
    # Refitting on resize must go through the gutter check, not fit.fit()
    # directly, or a window resize silently reintroduces the overlap.
    assert "setTimeout(() => { fitTerminal(); sendResize(); }" in page


def test_the_scrollbar_width_agrees_between_css_and_js(page):
    """The trim arithmetic reserves SCROLLBAR_PX; the stylesheet decides how
    wide the bar actually is. If they drift apart the gutter is either too
    narrow to reach or wider than it needs to be."""
    css = re.search(r"::-webkit-scrollbar\s*{\s*width:\s*(\d+)px", page)
    js = re.search(r"SCROLLBAR_PX\s*=\s*(\d+)", page)
    assert css and js, "could not find both the CSS width and the JS constant"
    assert css.group(1) == js.group(1), \
        f"CSS scrollbar is {css.group(1)}px but JS reserves {js.group(1)}px"
