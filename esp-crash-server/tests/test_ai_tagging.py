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
    assert kwargs["model"] == "claude-sonnet-5"
    assert kwargs["betas"] == ["mcp-client-2025-11-20"]
    assert kwargs["mcp_servers"][0]["url"] == "https://mcp-esp-crash.example/mcp"
    assert kwargs["mcp_servers"][0]["authorization_token"] == "svc-token"
    assert kwargs["tools"] == [{"type": "mcp_toolset", "mcp_server_name": "esp-crash"}]
    assert str(crash_id) in kwargs["messages"][0]["content"]

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_summary FROM crash WHERE crash_id = %s", (crash_id,))
        assert cur.fetchone()[0] == summary_text
