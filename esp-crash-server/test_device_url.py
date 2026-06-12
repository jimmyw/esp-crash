from device_url import (
    DEVICE_ID_PLACEHOLDER,
    device_url_template_is_valid,
    resolve_device_url,
)


def test_placeholder_token_is_device_id():
    assert DEVICE_ID_PLACEHOLDER == "{device_id}"


def test_resolve_substitutes_device_id():
    url = resolve_device_url("https://www.example.com/search/{device_id}", "ABC123")
    assert url == "https://www.example.com/search/ABC123"


def test_resolve_url_encodes_device_id():
    url = resolve_device_url("https://x.test/s/{device_id}", "a b/c?d")
    assert url == "https://x.test/s/a%20b%2Fc%3Fd"


def test_resolve_returns_none_for_blank_template():
    assert resolve_device_url("", "ABC123") is None
    assert resolve_device_url(None, "ABC123") is None


def test_resolve_returns_none_when_placeholder_missing():
    assert resolve_device_url("https://x.test/no-token", "ABC123") is None


def test_resolve_handles_missing_device_id():
    assert resolve_device_url("https://x.test/s/{device_id}", None) == "https://x.test/s/"


def test_validation_blank_is_valid():
    assert device_url_template_is_valid("") is True
    assert device_url_template_is_valid("   ") is True
    assert device_url_template_is_valid(None) is True


def test_validation_requires_placeholder_when_non_blank():
    assert device_url_template_is_valid("https://x.test/s/{device_id}") is True
    assert device_url_template_is_valid("https://x.test/no-token") is False


# --- scheme-safety tests (Change 2) ---


def test_validation_rejects_javascript_scheme():
    assert device_url_template_is_valid("javascript:alert(1)/{device_id}") is False


def test_validation_rejects_ftp_scheme():
    assert device_url_template_is_valid("ftp://x.test/{device_id}") is False


def test_validation_accepts_http_scheme():
    assert device_url_template_is_valid("http://x.test/{device_id}") is True


def test_validation_accepts_https_scheme_case_insensitive():
    assert device_url_template_is_valid("HTTPS://X.TEST/{device_id}") is True


def test_resolve_returns_none_for_javascript_scheme():
    assert resolve_device_url("javascript:alert(1)/{device_id}", "ABC") is None


def test_resolve_returns_none_for_ftp_scheme():
    assert resolve_device_url("ftp://x.test/{device_id}", "ABC") is None
