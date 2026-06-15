"""Unit tests for Network Feed validation and rendering."""
import json

import pytest

from app.routers.ui import DEFAULT_NETFEED_ENTRIES, parse_entries_text
from app.schemas.network_feed import validate_domain, validate_entry
from app.services.render import normalize_network_feed_content, render_network_feed


class _FakeFeed:
    def __init__(self, content: dict):
        self.content = content


def test_validate_domain_fqdn():
    assert validate_domain("host.example.com") == "host.example.com"


def test_validate_domain_wildcard():
    assert validate_domain("*.example.com") == "*.example.com"


def test_validate_domain_rejects_bare_label():
    with pytest.raises(ValueError):
        validate_domain("localhost")  # no dot → not an FQDN


def test_validate_domain_rejects_ip_like():
    with pytest.raises(ValueError):
        validate_domain("1.2.3.4")  # all-numeric TLD


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


def test_normalize_rejects_empty():
    with pytest.raises(Exception):
        normalize_network_feed_content([], "ip_domain", "flat")


def test_render_flat_list():
    content = normalize_network_feed_content(["1.2.3.4", "*.evil.com"], "ip_domain", "flat")
    body, media = render_network_feed(_FakeFeed(content))
    assert media.startswith("text/plain")
    assert body == "1.2.3.4\n*.evil.com\n"


def test_render_json_mode():
    content = normalize_network_feed_content(["1.2.3.4"], "ip", "json")
    body, media = render_network_feed(_FakeFeed(content))
    assert media == "application/json"
    assert json.loads(body) == {"entries": ["1.2.3.4"]}


def test_default_netfeed_example_is_valid():
    content = normalize_network_feed_content(parse_entries_text(DEFAULT_NETFEED_ENTRIES), "ip_domain", "flat")
    assert len(content["entries"]) == 5
