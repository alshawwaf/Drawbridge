"""Feed edit: the create forms are reused for editing, so content must serialize back to the
quick-entry text format and re-parse to the same feed. Also covers the credential rules (blank
password keeps the stored one; clearing the username, or a username with no password, → open feed)."""
from app.models import FeedType
from app.routers.ui import _feed_build_form, _feed_parse_edit


class FakeFeed:
    def __init__(self, type, content, name="F", description="d", interval_seconds=60,
                 auth_header_key=None, auth_header_value=None):
        self.id, self.type, self.content, self.name = 1, type, content, name
        self.description, self.interval_seconds = description, interval_seconds
        self.auth_header_key, self.auth_header_value = auth_header_key, auth_header_value


def _roundtrip(feed):
    """build_form (content → text) then parse (text → content) — the form dict doubles as the raw form."""
    content, updates = _feed_parse_edit(feed, _feed_build_form(feed))
    return content, updates


def test_generic_round_trips_objects():
    feed = FakeFeed(FeedType.generic_dc, {"objects": [
        {"name": "Obj A", "id": "x", "description": "demo", "ranges": ["10.0.0.0/24", "1.2.3.4"]}]})
    content, _ = _roundtrip(feed)
    o = content["objects"][0]
    assert o["name"] == "Obj A" and o["ranges"] == ["10.0.0.0/24", "1.2.3.4"] and o["description"] == "demo"


def test_network_flat_round_trips():
    feed = FakeFeed(FeedType.network_feed, {"format": "flat", "data_type": "ip",
                                            "entries": ["203.0.113.10", "198.51.100.0/24"]})
    content, _ = _roundtrip(feed)
    assert content == {"format": "flat", "data_type": "ip", "entries": ["203.0.113.10", "198.51.100.0/24"]}


def test_network_json_round_trips():
    body = '{"blocklist":[{"value":"1.2.3.4"}]}'
    feed = FakeFeed(FeedType.network_feed, {"format": "json", "data_type": "ip_domain",
                                            "jq_query": ".blocklist[].value", "body": body})
    content, _ = _roundtrip(feed)
    assert content["format"] == "json" and content["jq_query"] == ".blocklist[].value" and content["body"] == body


def test_ioc_cp_csv_round_trips():
    feed = FakeFeed(FeedType.ioc, {"format": "cp_csv", "indicators": [
        {"name": "ioc-1", "value": "203.0.113.66", "type": "IP", "confidence": "high",
         "severity": "high", "product": "AB", "comment": "C2 beacon"}]})
    content, _ = _roundtrip(feed)
    i = content["indicators"][0]
    assert (i["value"], i["type"], i["confidence"], i["comment"]) == ("203.0.113.66", "IP", "high", "C2 beacon")


def test_ioc_snort_round_trips():
    feed = FakeFeed(FeedType.ioc, {"format": "snort",
                                   "rules": ['alert tcp any any -> any 80 (msg:"x"; sid:1000001;)']})
    content, _ = _roundtrip(feed)
    assert content["format"] == "snort" and "sid:1000001" in content["rules"][0]


_IOC = {"name": "F", "ioc_format": "cp_csv", "indicators_text": "1.2.3.4, IP"}


def test_blank_password_keeps_stored_value():
    feed = FakeFeed(FeedType.ioc, {"format": "cp_csv", "indicators": []},
                    auth_header_key="user", auth_header_value="kept")
    _, updates = _feed_parse_edit(feed, {**_IOC, "basic_user": "user2", "basic_pass": ""})
    assert updates["auth_header_key"] == "user2"      # username updated from the form
    assert updates["auth_header_value"] == "kept"     # password left blank → stored value kept


def test_new_password_replaces_value():
    feed = FakeFeed(FeedType.ioc, {"format": "cp_csv", "indicators": []},
                    auth_header_key="user", auth_header_value="old")
    _, updates = _feed_parse_edit(feed, {**_IOC, "basic_user": "user", "basic_pass": "new"})
    assert updates["auth_header_value"] == "new"


def test_clearing_username_reverts_to_open():
    feed = FakeFeed(FeedType.ioc, {"format": "cp_csv", "indicators": []},
                    auth_header_key="user", auth_header_value="x")
    _, updates = _feed_parse_edit(feed, {**_IOC, "basic_user": "", "basic_pass": ""})
    assert updates["auth_header_key"] is None and updates["auth_header_value"] is None


def test_username_without_password_is_open():
    feed = FakeFeed(FeedType.ioc, {"format": "cp_csv", "indicators": []})  # no stored auth
    _, updates = _feed_parse_edit(feed, {**_IOC, "basic_user": "user", "basic_pass": ""})
    assert updates["auth_header_key"] is None  # a username with no password ≠ a configured feed
