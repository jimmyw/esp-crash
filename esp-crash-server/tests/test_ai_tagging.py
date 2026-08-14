"""Tests for app/ai_tagging.py - mocks the anthropic client entirely (no
real API calls), verifying the request shape and that the returned summary
text is persisted."""
from app import ai_tagging

import helpers


class _FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeResponse:
    def __init__(self, text):
        self.content = [_FakeTextBlock(text)]


class _FakeMessages:
    def __init__(self, response, calls):
        self._response = response
        self._calls = calls

    def create(self, **kwargs):
        self._calls.append(kwargs)
        return self._response


class _FakeBeta:
    def __init__(self, response, calls):
        self.messages = _FakeMessages(response, calls)


class _FakeAnthropicClient:
    def __init__(self, response, calls):
        self.beta = _FakeBeta(response, calls)


def test_summarize_and_tag_writes_summary_and_calls_mcp_connector(app, db_conn, monkeypatch):
    calls = []
    summary_text = "Stack overflow in task X caused by a large local buffer."
    fake_response = _FakeResponse(summary_text)
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(fake_response, calls),
    )

    helpers.create_project(db_conn, "proj-ai-1", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-1")
    crash_id = helpers.create_crash(db_conn, "proj-ai-1", "1.0", device_id, dump="symbolicated text")

    app.config["ANTHROPIC_API_KEY"] = "sk-test"
    app.config["MCP_PUBLIC_URL"] = "https://mcp-esp-crash.example"
    app.config["MCP_SERVICE_TOKEN"] = "svc-token"

    with app.app_context():
        result = ai_tagging.summarize_and_tag(crash_id, "proj-ai-1")

    assert result == summary_text
    assert len(calls) == 1
    kwargs = calls[0]
    assert kwargs["model"] == "claude-haiku-4-5"
    assert kwargs["betas"] == ["mcp-client-2025-11-20"]
    assert kwargs["mcp_servers"][0]["url"] == "https://mcp-esp-crash.example/mcp"
    assert kwargs["mcp_servers"][0]["authorization_token"] == "svc-token"
    assert kwargs["tools"] == [{"type": "mcp_toolset", "mcp_server_name": "esp-crash"}]
    assert str(crash_id) in kwargs["messages"][0]["content"]

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_summary FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == summary_text


def test_summarize_and_tag_reuses_exact_duplicate_without_calling_api(app, db_conn, monkeypatch):
    calls = []

    def fail_if_called(api_key=None):
        raise AssertionError("Anthropic client should not be constructed for an exact-content duplicate")

    monkeypatch.setattr(ai_tagging, "Anthropic", fail_if_called)

    helpers.create_project(db_conn, "proj-ai-dup", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-dup")
    same_dump = "identical symbolicated backtrace"

    source_id = helpers.create_crash(
        db_conn, "proj-ai-dup", "1.0", device_id,
        dump=same_dump, ai_summary="Watchdog fired in ota_manifest task.",
    )
    tag_id = helpers.create_tag(db_conn, "proj-ai-dup", "watchdog")
    helpers.tag_crash(db_conn, source_id, tag_id)

    new_id = helpers.create_crash(db_conn, "proj-ai-dup", "1.0", device_id, dump=same_dump)

    app.config["ANTHROPIC_API_KEY"] = "sk-test"
    app.config["MCP_PUBLIC_URL"] = "https://mcp-esp-crash.example"
    app.config["MCP_SERVICE_TOKEN"] = "svc-token"

    with app.app_context():
        result = ai_tagging.summarize_and_tag(new_id, "proj-ai-dup")

    assert calls == []
    assert str(source_id) in result
    assert "Watchdog fired in ota_manifest task." in result

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_summary FROM crash WHERE crash_id = %s", (new_id,))
        assert "Watchdog fired in ota_manifest task." in cur.fetchone()[0]
        cur.execute(
            "SELECT t.name FROM tag t JOIN crash_tag ct ON ct.tag_id = t.tag_id WHERE ct.crash_id = %s",
            (new_id,),
        )
        assert cur.fetchone()[0] == "watchdog"


def test_summarize_and_tag_ignores_duplicates_from_other_projects(app, db_conn, monkeypatch):
    """Same dump text in a different project must not be treated as a
    duplicate - tags are project-scoped and coincidental content matches
    across unrelated projects shouldn't short-circuit real analysis."""
    calls = []
    summary_text = "Fresh analysis, no duplicate found."
    fake_response = _FakeResponse(summary_text)
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(fake_response, calls),
    )

    same_dump = "identical text, different project"
    helpers.create_project(db_conn, "proj-ai-other-a", github_user="alice")
    device_a = helpers.create_device(db_conn, "dev-ai-other-a")
    helpers.create_crash(
        db_conn, "proj-ai-other-a", "1.0", device_a,
        dump=same_dump, ai_summary="Summary from a different project.",
    )

    helpers.create_project(db_conn, "proj-ai-other-b", github_user="alice")
    device_b = helpers.create_device(db_conn, "dev-ai-other-b")
    new_id = helpers.create_crash(db_conn, "proj-ai-other-b", "1.0", device_b, dump=same_dump)

    app.config["ANTHROPIC_API_KEY"] = "sk-test"
    app.config["MCP_PUBLIC_URL"] = "https://mcp-esp-crash.example"
    app.config["MCP_SERVICE_TOKEN"] = "svc-token"

    with app.app_context():
        result = ai_tagging.summarize_and_tag(new_id, "proj-ai-other-b")

    assert len(calls) == 1
    assert result == summary_text
