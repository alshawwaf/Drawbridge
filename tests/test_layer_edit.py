"""Editing an existing Dynamic Layer: the builder renders in edit mode, and the content
parser builds + validates the submitted JSON (shared by create and update)."""
import json

import pytest

from app.routers.dynamic_layers import (
    DEFAULT_LAYER_CONTENT,
    _BUILDER_CTX,
    _parse_layer_content,
)
from app.routers.ui import templates
from app.schemas.dynamic_layer import build_set_dynamic_content, evaluate_dynamic_content


def _render(name, **ctx):
    ctx.setdefault("request", None)
    return templates.env.get_template(name).render(**ctx)


def _builder(**over):
    ctx = dict(_BUILDER_CTX)
    ctx.update({"action": "/layers/new", "is_edit": False, "cancel_url": "/layers",
                "error": None, "default_content": DEFAULT_LAYER_CONTENT, "gateways": [],
                "selected_gateway_id": "",
                "form": {"name": "L", "layer_name": "dynamic_layer", "description": "",
                         "comments": "", "tags": ""}})
    ctx.update(over)
    return ctx


def test_builder_edit_mode_posts_to_edit_and_returns_to_layer():
    html = _render("dynamic_new.html",
                   **_builder(action="/layers/5/edit", is_edit=True, cancel_url="/layers/5"))
    assert 'action="/layers/5/edit"' in html
    assert "Edit Dynamic Layer" in html and "Save changes" in html
    assert 'href="/layers/5"' in html  # Cancel returns to the layer, not the list


def test_builder_new_mode_unchanged():
    html = _render("dynamic_new.html", **_builder())
    assert 'action="/layers/new"' in html and "Save layer" in html


def test_builder_referenced_section_is_above_rules_and_not_optional():
    html = _render("dynamic_new.html", **_builder())
    assert html.index("Referenced objects") < html.index(">Rules<")  # referenced comes first
    assert "Referenced objects</h2>" in html  # the "(optional)" qualifier is gone


def test_parse_layer_content_builds_validates_and_coerces():
    c = _parse_layer_content(
        objects_json=json.dumps(DEFAULT_LAYER_CONTENT["objects"]),
        rules_json=json.dumps(DEFAULT_LAYER_CONTENT["rulebase"]),
        referenced_json="{}", comments="note", tags="a, b", gateway_id="3")
    assert c["operation"] == "replace"
    assert c["tags"] == ["a", "b"] and c["gateway_id"] == 3
    assert len(c["rulebase"]) == len(DEFAULT_LAYER_CONTENT["rulebase"]) and c["comments"] == "note"


def test_parse_layer_content_rejects_bad_json():
    with pytest.raises(Exception):
        _parse_layer_content(objects_json="{bad", rules_json="[]", referenced_json="{}",
                             comments="", tags="", gateway_id="")


class _DefaultLayer:
    layer_name = "dynamic_layer"
    content = DEFAULT_LAYER_CONTENT


def test_default_policy_ships_referenced_objects_used_by_rules():
    payload = build_set_dynamic_content(_DefaultLayer())
    refs = payload["referenced-objects"]
    assert "ssh" in refs.get("services-tcp", []) and "https" in refs.get("services-tcp", [])
    # at least one rule actually uses a referenced service name
    services = [r.get("service") for r in DEFAULT_LAYER_CONTENT["rulebase"]]
    assert any(isinstance(s, list) and "https" in s for s in services)
    # the default must apply on a plain Firewall layer — no applications/categories, which would
    # require the "Application & URL Filtering" blade to be enabled on the layer.
    assert "application-sites" not in refs and "application-site-categories" not in refs


def test_default_policy_validates_and_all_references_resolve():
    payload = build_set_dynamic_content(_DefaultLayer())
    result = evaluate_dynamic_content(payload)
    assert result["status"] == "succeeded"
    assert result["validation_warnings"] == []  # every name used in a rule resolves
