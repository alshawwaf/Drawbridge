"""Management web_api client: rulebase structuring + UID→name resolution (no live SMS needed)."""
from app.services import mgmt_api

OBJDICT = {
    "u-any": {"uid": "u-any", "name": "Any", "type": "CpmiAnyObject"},
    "u-net": {"uid": "u-net", "name": "dmz-net", "type": "network"},
    "u-web": {"uid": "u-web", "name": "web-srv", "type": "host"},
    "u-https": {"uid": "u-https", "name": "https", "type": "service-tcp"},
    "u-accept": {"uid": "u-accept", "name": "Accept", "type": "RulebaseAction"},
    "u-drop": {"uid": "u-drop", "name": "Drop", "type": "RulebaseAction"},
    "u-log": {"uid": "u-log", "name": "Log", "type": "Track"},
}

ITEMS = [
    {"type": "access-section", "name": "Web", "rulebase": [
        {"type": "access-rule", "rule-number": 1, "name": "Allow web", "enabled": True,
         "source": ["u-net"], "destination": ["u-web"], "service": ["u-https"],
         "action": "u-accept", "track": {"type": "u-log"}},
    ]},
    {"type": "access-rule", "rule-number": 2, "name": "Cleanup", "enabled": False,
     "source": ["u-any"], "destination": ["u-any"], "service": ["u-any"],
     "action": "u-drop", "track": {"type": "u-log"}, "source-negate": True},
    {"type": "place-holder", "name": "weird-thing"},   # unknown type → passthrough, never crash
]


def test_structure_resolves_uids_sections_and_negate():
    rows = mgmt_api._structure_rulebase(ITEMS, OBJDICT)
    kinds = [r["kind"] for r in rows]
    assert kinds == ["section", "rule", "rule", "other"]

    section, allow, cleanup, other = rows
    assert section["name"] == "Web"

    assert allow["name"] == "Allow web" and allow["enabled"] is True
    assert allow["source"] == ["dmz-net"] and allow["destination"] == ["web-srv"]
    assert allow["service"] == ["https"] and allow["action"] == "Accept" and allow["track"] == "Log"
    assert allow["source_negate"] is False

    assert cleanup["enabled"] is False and cleanup["action"] == "Drop"
    assert cleanup["source"] == ["Any"] and cleanup["source_negate"] is True

    assert other["type"] == "place-holder"   # unknown item flagged, not dropped or crashing


def test_obj_names_handles_uids_and_inline_dicts():
    assert mgmt_api._obj_names(["u-web", {"name": "inline-host"}], OBJDICT) == ["web-srv", "inline-host"]
    assert mgmt_api._obj_names(["u-missing"], OBJDICT) == ["u-missing"]   # unresolved UID → shown raw
    assert mgmt_api._one_name("u-accept", OBJDICT) == "Accept"
    assert mgmt_api._one_name({"name": "Reject"}, OBJDICT) == "Reject"
