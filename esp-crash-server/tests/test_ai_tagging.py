"""Tests for app/ai_tagging.py - mocks the anthropic client entirely (no
real API calls), verifying the request shape and that the returned
title/summary are persisted on the crash's relation (project_name,
signature) - see app/models.py."""
from app import ai_tagging

import helpers


class _FakeTextBlock:
    def __init__(self, text):
        self.type = "text"
        self.text = text


class _FakeToolUseBlock:
    """Stands in for an mcp_tool_use/mcp_tool_result block - anything
    non-text - without needing the real SDK's block shape."""
    def __init__(self):
        self.type = "mcp_tool_use"


class _FakeResponse:
    def __init__(self, text=None, blocks=None):
        self.content = blocks if blocks is not None else [_FakeTextBlock(text)]


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


def _title_description_text(title, description):
    return f"TITLE: {title}\nDESCRIPTION: {description}"


def _configure(app):
    app.config["ANTHROPIC_API_KEY"] = "sk-test"
    app.config["MCP_PUBLIC_URL"] = "https://mcp-esp-crash.example"
    app.config["MCP_SERVICE_TOKEN"] = "svc-token"


def test_summarize_and_tag_writes_title_and_summary_to_relation(app, db_conn, monkeypatch):
    calls = []
    title = "Stack overflow in task X"
    description = "Stack overflow in task X caused by a large local buffer."
    fake_response = _FakeResponse(_title_description_text(title, description))
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(fake_response, calls),
    )

    helpers.create_project(db_conn, "proj-ai-1", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-1")
    sig = "a" * 64
    crash_id = helpers.create_crash(db_conn, "proj-ai-1", "1.0", device_id, dump="symbolicated text", signature=sig)

    _configure(app)
    with app.app_context():
        result = ai_tagging.summarize_and_tag(crash_id, "proj-ai-1")

    assert result == {"title": title, "summary": description}
    assert len(calls) == 1
    kwargs = calls[0]
    assert kwargs["model"] == "claude-haiku-4-5"
    assert kwargs["betas"] == ["mcp-client-2025-11-20"]
    assert kwargs["mcp_servers"][0]["url"] == "https://mcp-esp-crash.example/mcp"
    assert kwargs["mcp_servers"][0]["authorization_token"] == "svc-token"
    assert kwargs["tools"] == [{"type": "mcp_toolset", "mcp_server_name": "esp-crash"}]
    prompt = kwargs["messages"][0]["content"]
    assert str(crash_id) in prompt
    # Framed as a group review, not a single occurrence - "1 crash" here
    # since this is the only crash sharing this signature.
    assert "one of 1 crashes" in prompt

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_title, ai_summary FROM crash_relation WHERE project_name = %s AND signature = %s", ("proj-ai-1", sig))
        assert cur.fetchone() == (title, description)


def test_summarize_and_tag_prompt_reports_group_size(app, db_conn, monkeypatch):
    calls = []
    fake_response = _FakeResponse(_title_description_text("T", "D"))
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(fake_response, calls),
    )

    helpers.create_project(db_conn, "proj-ai-group", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-group")
    sig = "b" * 64
    crash_1 = helpers.create_crash(db_conn, "proj-ai-group", "1.0", device_id, dump="dump 1", signature=sig)
    helpers.create_crash(db_conn, "proj-ai-group", "1.0", device_id, dump="dump 2", signature=sig)
    helpers.create_crash(db_conn, "proj-ai-group", "1.0", device_id, dump="dump 3", signature=sig)

    _configure(app)
    with app.app_context():
        ai_tagging.summarize_and_tag(crash_1, "proj-ai-group")

    prompt = calls[0]["messages"][0]["content"]
    assert "one of 3 crashes" in prompt


def test_summarize_and_tag_strips_narration_between_tool_calls(app, db_conn, monkeypatch):
    """response.content is the full flattened transcript of the server-side
    tool-use turns - text blocks Claude produced before/between tool calls
    ("I'll start by...", "Now I'll tag this...") must not end up glued onto
    the stored title/summary; only the trailing run of text blocks (the
    final answer) should."""
    calls = []
    title = "Division by zero in beacon parser"
    description = "A division by zero occurred in the WiFi beacon parser."
    blocks = [
        _FakeTextBlock("I'll help you analyze the crash. Let me start by getting the details."),
        _FakeToolUseBlock(),
        _FakeTextBlock("Now I'll tag this crash with the appropriate tags."),
        _FakeToolUseBlock(),
        _FakeTextBlock(_title_description_text(title, description)),
    ]
    fake_response = _FakeResponse(blocks=blocks)
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(fake_response, calls),
    )

    helpers.create_project(db_conn, "proj-ai-narration", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-narration")
    sig = "c" * 64
    crash_id = helpers.create_crash(db_conn, "proj-ai-narration", "1.0", device_id, dump="symbolicated text", signature=sig)

    _configure(app)
    with app.app_context():
        result = ai_tagging.summarize_and_tag(crash_id, "proj-ai-narration")

    assert result == {"title": title, "summary": description}
    assert "I'll help you analyze" not in result["summary"]
    assert "Now I'll tag this crash" not in result["summary"]

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_title, ai_summary FROM crash_relation WHERE project_name = %s AND signature = %s", ("proj-ai-narration", sig))
        assert cur.fetchone() == (title, description)


def test_summarize_and_tag_joins_multiple_trailing_text_blocks(app, db_conn, monkeypatch):
    calls = []
    blocks = [
        _FakeToolUseBlock(),
        _FakeTextBlock("TITLE: Foo bar crash\n"),
        _FakeTextBlock("DESCRIPTION: First part."),
        _FakeTextBlock("Second part."),
    ]
    fake_response = _FakeResponse(blocks=blocks)
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(fake_response, calls),
    )

    helpers.create_project(db_conn, "proj-ai-multi-text", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-multi-text")
    sig = "d" * 64
    crash_id = helpers.create_crash(db_conn, "proj-ai-multi-text", "1.0", device_id, dump="symbolicated text", signature=sig)

    _configure(app)
    with app.app_context():
        result = ai_tagging.summarize_and_tag(crash_id, "proj-ai-multi-text")

    assert result == {"title": "Foo bar crash", "summary": "First part.\n\nSecond part."}


def test_summarize_and_tag_raises_on_unparseable_format(app, db_conn, monkeypatch):
    """If the model doesn't follow the TITLE:/DESCRIPTION: format, raise
    rather than store garbage - the relation's ai_summary stays NULL so
    cron retries the group later."""
    calls = []
    fake_response = _FakeResponse("Just a plain sentence with no format at all.")
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(fake_response, calls),
    )

    helpers.create_project(db_conn, "proj-ai-badformat", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-badformat")
    sig = "e" * 64
    crash_id = helpers.create_crash(db_conn, "proj-ai-badformat", "1.0", device_id, dump="symbolicated text", signature=sig)

    _configure(app)
    with app.app_context():
        try:
            ai_tagging.summarize_and_tag(crash_id, "proj-ai-badformat")
            assert False, "expected ValueError"
        except ValueError:
            pass

    with db_conn.cursor() as cur:
        cur.execute("SELECT ai_title, ai_summary FROM crash_relation WHERE project_name = %s AND signature = %s", ("proj-ai-badformat", sig))
        assert cur.fetchone() == (None, None)


def test_summarize_and_tag_raises_for_unsignatured_crash(app, db_conn, monkeypatch):
    """cron only ever selects crashes with a signature - this is a
    defensive check, not a normal path. No API call either way."""
    calls = []
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(_FakeResponse("unused"), calls),
    )

    helpers.create_project(db_conn, "proj-ai-nosig", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-nosig")
    crash_id = helpers.create_crash(db_conn, "proj-ai-nosig", "1.0", device_id, dump="symbolicated text")

    _configure(app)
    with app.app_context():
        try:
            ai_tagging.summarize_and_tag(crash_id, "proj-ai-nosig")
            assert False, "expected ValueError"
        except ValueError:
            pass
    assert calls == []


def test_summarize_and_tag_reuses_existing_relation_review_without_calling_api(app, db_conn, monkeypatch):
    """If another crash in the same group already triggered a review
    (or the relation was reviewed on a previous cron tick), the relation
    already has ai_summary set - no API call needed, just read it back.
    This is the group-owning-row replacement for the old per-crash
    duplicate-detection logic."""
    calls = []

    def fail_if_called(api_key=None):
        raise AssertionError("Anthropic client should not be constructed when the relation is already reviewed")

    monkeypatch.setattr(ai_tagging, "Anthropic", fail_if_called)

    helpers.create_project(db_conn, "proj-ai-dup", github_user="alice")
    device_id = helpers.create_device(db_conn, "dev-ai-dup")
    sig = "f" * 64
    # First crash in the group already reviewed (its own summarize_and_tag
    # call, or a previous cron tick, already ran).
    helpers.create_crash(
        db_conn, "proj-ai-dup", "1.0", device_id,
        dump="dump 1", signature=sig, ai_title="Watchdog fired", ai_summary="Watchdog fired in ota_manifest task.",
    )
    new_id = helpers.create_crash(db_conn, "proj-ai-dup", "1.0", device_id, dump="dump 2", signature=sig)

    _configure(app)
    with app.app_context():
        result = ai_tagging.summarize_and_tag(new_id, "proj-ai-dup")

    assert calls == []
    assert result == {"title": "Watchdog fired", "summary": "Watchdog fired in ota_manifest task."}


def test_summarize_and_tag_different_projects_reviewed_independently(app, db_conn, monkeypatch):
    """crash_relation is keyed by (project_name, signature) - an
    already-reviewed group in one project must not short-circuit a fresh
    review for the same signature string in a different project."""
    calls = []
    fake_response = _FakeResponse(_title_description_text("Fresh title", "Fresh analysis, no duplicate found."))
    monkeypatch.setattr(
        ai_tagging, "Anthropic",
        lambda api_key=None: _FakeAnthropicClient(fake_response, calls),
    )

    sig = "9" * 64
    helpers.create_project(db_conn, "proj-ai-other-a", github_user="alice")
    device_a = helpers.create_device(db_conn, "dev-ai-other-a")
    helpers.create_crash(
        db_conn, "proj-ai-other-a", "1.0", device_a,
        dump="dump a", signature=sig, ai_title="Other project title", ai_summary="Summary from a different project.",
    )

    helpers.create_project(db_conn, "proj-ai-other-b", github_user="alice")
    device_b = helpers.create_device(db_conn, "dev-ai-other-b")
    new_id = helpers.create_crash(db_conn, "proj-ai-other-b", "1.0", device_b, dump="dump b", signature=sig)

    _configure(app)
    with app.app_context():
        result = ai_tagging.summarize_and_tag(new_id, "proj-ai-other-b")

    assert len(calls) == 1
    assert result == {"title": "Fresh title", "summary": "Fresh analysis, no duplicate found."}
