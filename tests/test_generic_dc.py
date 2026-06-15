"""Unit tests for the Generic Data Center format logic (sk167210 compliance)."""
import json
import uuid

import pytest

from app.routers.ui import DEFAULT_OBJECTS_TEXT, parse_objects_text
from app.schemas.generic_dc import GENERIC_DC_VERSION, validate_range
from app.services.render import normalize_generic_dc_content, render_generic_dc


class _FakeFeed:
    def __init__(self, content, description=""):
        self.content = content
        self.description = description


def test_validate_range_single_ipv4():
    assert validate_range("91.198.174.192") == "91.198.174.192"


def test_validate_range_cidr():
    assert validate_range("20.0.0.0/24") == "20.0.0.0/24"


def test_validate_range_inclusive_range():
    assert validate_range("10.1.1.2-10.1.1.10") == "10.1.1.2-10.1.1.10"


def test_validate_range_ipv6():
    assert validate_range("2001:0db8:85a3:0000:0000:8a2e:0370:7334")


def test_validate_range_rejects_garbage():
    with pytest.raises(ValueError):
        validate_range("not-an-ip")


def test_validate_range_rejects_reversed_range():
    with pytest.raises(ValueError):
        validate_range("10.0.0.10-10.0.0.1")


def test_validate_range_rejects_mixed_versions():
    with pytest.raises(ValueError):
        validate_range("10.0.0.1-2001:db8::1")


def test_normalize_assigns_uuid_when_missing():
    content = normalize_generic_dc_content([{"name": "web", "ranges": ["10.0.0.0/24"]}])
    obj = content["objects"][0]
    uuid.UUID(obj["id"])  # must be a valid UUID
    assert obj["name"] == "web"


def test_normalize_preserves_supplied_uuid():
    given = "e7f18b60-f22d-4f42-8dc2-050490ecf6d5"
    content = normalize_generic_dc_content([{"name": "a", "id": given, "ranges": ["1.1.1.1"]}])
    assert content["objects"][0]["id"] == given


def test_normalize_rejects_bad_uuid():
    with pytest.raises(Exception):
        normalize_generic_dc_content([{"name": "a", "id": "nope", "ranges": ["1.1.1.1"]}])


def test_normalize_rejects_empty_ranges():
    with pytest.raises(Exception):
        normalize_generic_dc_content([{"name": "a", "ranges": []}])


def test_render_emits_spec_compliant_json():
    content = normalize_generic_dc_content(
        [{"name": "Object A", "description": "demo", "ranges": ["91.198.174.192", "20.0.0.0/24"]}]
    )
    feed = _FakeFeed(content, description="Generic Data Center file example")
    body, media = render_generic_dc(feed)
    assert media == "application/json"
    doc = json.loads(body)
    assert doc["version"] == GENERIC_DC_VERSION == "1.0"
    assert doc["description"] == "Generic Data Center file example"
    o = doc["objects"][0]
    assert set(("name", "id", "ranges")).issubset(o)  # mandatory fields present
    assert o["ranges"] == ["91.198.174.192", "20.0.0.0/24"]


def test_parse_objects_basic():
    objs = parse_objects_text("web = 10.0.0.0/24, 1.2.3.4")
    assert objs == [{"name": "web", "description": "", "ranges": ["10.0.0.0/24", "1.2.3.4"]}]


def test_parse_objects_optional_description():
    objs = parse_objects_text("A = 1.1.1.1 | Example for IPv4 addresses")
    assert objs[0]["description"] == "Example for IPv4 addresses"
    assert objs[0]["ranges"] == ["1.1.1.1"]


def test_parse_objects_rejects_missing_separator():
    with pytest.raises(ValueError):
        parse_objects_text("no separator here")


def test_default_example_is_valid_and_complete():
    """The pre-filled form default must always parse and pass CP-schema validation."""
    content = normalize_generic_dc_content(parse_objects_text(DEFAULT_OBJECTS_TEXT))
    assert len(content["objects"]) == 2
    assert content["objects"][0]["description"] == "Example for IPv4 addresses"
    assert content["objects"][1]["description"] == "Example for IPv6 addresses"
