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


def test_parse_layer_content_builds_validates_and_coerces():
    c = _parse_layer_content(
        objects_json=json.dumps(DEFAULT_LAYER_CONTENT["objects"]),
        rules_json=json.dumps(DEFAULT_LAYER_CONTENT["rulebase"]),
        referenced_json="{}", comments="note", tags="a, b", gateway_id="3")
    assert c["operation"] == "replace"
    assert c["tags"] == ["a", "b"] and c["gateway_id"] == 3
    assert len(c["rulebase"]) == 2 and c["comments"] == "note"


def test_parse_layer_content_rejects_bad_json():
    with pytest.raises(Exception):
        _parse_layer_content(objects_json="{bad", rules_json="[]", referenced_json="{}",
                             comments="", tags="", gateway_id="")
