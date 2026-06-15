"""Unit tests for Network Feed validation and rendering."""
import pytest

from app.routers.ui import (
    DEFAULT_JQ_QUERY,
    DEFAULT_NETFEED_ENTRIES,
    DEFAULT_NETFEED_JSON_BODY,
    NETFEED_EXAMPLES,
    parse_entries_text,
)
from app.schemas.network_feed import validate_domain, validate_entry, validate_json_body
from app.services.render import (
    normalize_network_feed_flat,
    normalize_network_feed_json,
    render_network_feed,
)


class _FakeFeed:
    def __init__(self, content: dict):
        self.content = content


# --- domain / entry validation --------------------------------------------------------
def test_validate_domain_fqdn():
    assert validate_domain("host.example.com") == "host.example.com"


def test_validate_domain_wildcard():
    assert validate_domain("*.example.com") == "*.example.com"


def test_validate_domain_rejects_bare_label():
    with pytest.raises(ValueError):
        validate_domain("localhost")


def test_validate_domain_rejects_ip_like():
    with pytest.raises(ValueError):
        validate_domain("1.2.3.4")


def test_entry_ip_mode_accepts_cidr_and_range():
    assert validate_entry("10.0.0.0/24", "ip") == "10.0.0.0/24"
    assert validate_entry("10.0.0.1-10.0.0.9", "ip") == "10.0.0.1-10.0.0.9"


def test_entry_ip_mode_rejects_domain():
    with pytest.raises(ValueError):
        validate_entry("evil.com", "ip")


def test_entry_domain_mode_rejects_ip():
    with pytest.raises(ValueError):
        validate_entry("1.2.3.4", "domain")


def test_entry_ip_domain_accepts_both():
    assert validate_entry("1.2.3.4", "ip_domain") == "1.2.3.4"
    assert validate_entry("*.evil.com", "ip_domain") == "*.evil.com"
    assert validate_entry("bad-host.example.net", "ip_domain") == "bad-host.example.net"


# --- flat list ------------------------------------------------------------------------
def test_flat_rejects_empty():
    with pytest.raises(ValueError):
        normalize_network_feed_flat([], "ip_domain")


def test_render_flat_list():
    content = normalize_network_feed_flat(["1.2.3.4", "*.evil.com"], "ip_domain")
    body, media = render_network_feed(_FakeFeed(content))
    assert media.startswith("text/plain")
    assert body == "1.2.3.4\n*.evil.com\n"


# --- custom JSON (free-form body + JQ query) ------------------------------------------
def test_json_valid_returns_body_and_query():
    body = '{"x": ["a", "b"]}'
    content = normalize_network_feed_json(body, ".x[]", "domain")
    assert content["format"] == "json"
    assert content["jq_query"] == ".x[]"
    assert content["body"] == body


def test_json_invalid_raises():
    with pytest.raises(ValueError):
        normalize_network_feed_json("{not json", ".x[]", "ip")


def test_json_requires_jq_query():
    with pytest.raises(ValueError):
        normalize_network_feed_json('{"x": []}', "   ", "ip")


def test_render_json_verbatim():
    body = '{\n  "blocklist": ["a", "b"]\n}'
    content = normalize_network_feed_json(body, ".blocklist[]", "domain")
    out, media = render_network_feed(_FakeFeed(content))
    assert media == "application/json"
    assert out == body  # served exactly as authored, not reshaped


# --- defaults guard -------------------------------------------------------------------
def test_default_netfeed_flat_example_is_valid():
    content = normalize_network_feed_flat(parse_entries_text(DEFAULT_NETFEED_ENTRIES), "ip_domain")
    assert len(content["entries"]) == 5


def test_each_example_validates_under_its_data_type():
    for data_type, text in NETFEED_EXAMPLES.items():
        content = normalize_network_feed_flat(parse_entries_text(text), data_type)
        assert content["entries"], f"example for {data_type} failed to validate"


def test_default_json_body_is_valid():
    validate_json_body(DEFAULT_NETFEED_JSON_BODY)  # must not raise
    content = normalize_network_feed_json(DEFAULT_NETFEED_JSON_BODY, DEFAULT_JQ_QUERY, "domain")
    assert content["jq_query"] == DEFAULT_JQ_QUERY
