"""Management web_api client: rulebase structuring + UID→name resolution (no live SMS needed)."""
from app.services import mgmt_api, mgmt_export

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


# --- IaC export (mgmt_export.generate) ------------------------------------------------------

EXPORT_BUNDLE = {
    "layer": "Network",
    "objects_by_type": {
        "host": [{"uid": "u-web", "name": "web-srv", "type": "host", "ipv4-address": "10.0.0.5",
                  "domain": {"domain-type": "domain"}}],
        "network": [{"uid": "u-net", "name": "dmz-net", "type": "network",
                     "subnet4": "10.0.0.0", "mask-length4": 24}],
        "group": [{"uid": "u-grp", "name": "web-grp", "type": "group", "members": [{"name": "web-srv"}]}],
        "service-tcp": [{"uid": "u-svc", "name": "tcp-8443", "type": "service-tcp", "port": "8443"}],
        "dns-domain": [{"uid": "u-dns", "name": ".example.com", "type": "dns-domain"}],  # no spec → skipped
    },
    "rules": [
        {"kind": "section", "name": "Web"},
        {"kind": "rule", "number": 1, "name": "Allow web", "enabled": True,
         "source": ["web-grp"], "destination": ["web-srv"], "service": ["tcp-8443"], "vpn": [],
         "action": "Accept", "track": "Log", "comments": "ok",
         "source_negate": False, "destination_negate": False, "service_negate": False},
        {"kind": "rule", "number": 2, "name": "Cleanup", "enabled": False,
         "source": [], "destination": [], "service": [], "vpn": [],
         "action": "Drop", "track": "None", "source_negate": True},
    ],
}


def test_export_stats_count_and_skip_unknown_types():
    art = mgmt_export.generate(EXPORT_BUNDLE)
    s = art["stats"]
    assert s["objects"] == 4 and s["rules"] == 2 and s["sections"] == 1
    assert s["skipped"] == {"dns-domain": 1}            # unknown type counted, never crashes


def test_export_terraform_resources_refs_and_rule_cells():
    tf = mgmt_export.generate(EXPORT_BUNDLE)["terraform"]
    assert 'resource "checkpoint_management_host" "web_srv"' in tf
    assert 'ipv4_address = "10.0.0.5"' in tf
    assert "mask_length4 = 24" in tf                    # int rendered bare, not quoted
    # group members + rule cells resolve to real resource addresses (dependency wiring)
    assert "members = [checkpoint_management_host.web_srv.name]" in tf
    assert "source = [checkpoint_management_group.web_grp.name]" in tf
    assert 'action = "Accept"' in tf and 'type = "Log"' in tf
    assert 'source = ["Any"]' in tf                     # empty cleanup cell → Any
    assert "enabled = false" in tf and "source_negate = true" in tf
    assert "depends_on = [checkpoint_management_access_section.sec_web]" in tf  # order chain


def test_export_predefined_objects_are_referenced_not_emitted():
    # "Any" is referenced as a literal string but never gets its own resource block.
    tf = mgmt_export.generate(EXPORT_BUNDLE)["terraform"]
    assert '"any"' not in tf.lower().replace('["any"]', "")  # no resource named any
    assert mgmt_export.is_predefined({"type": "host", "domain": {"domain-type": "data domain"}})
    assert mgmt_export.is_predefined({"name": "Any", "type": "CpmiAnyObject"})
    assert not mgmt_export.is_predefined({"name": "web-srv", "type": "host",
                                          "domain": {"domain-type": "domain"}})


def test_export_ansible_and_mgmt_cli_shape():
    art = mgmt_export.generate(EXPORT_BUNDLE)
    ans, cli = art["ansible"], art["mgmt_cli"]
    assert "check_point.mgmt.cp_mgmt_host:" in ans and "state: present" in ans
    assert "check_point.mgmt.cp_mgmt_access_rule:" in ans and "position: bottom" in ans
    assert "check_point.mgmt.cp_mgmt_publish:" in ans
    assert 'mgmt_cli add host name "web-srv" ip-address "10.0.0.5"' in cli
    assert 'mgmt_cli add access-rule layer "Network" position bottom' in cli
    assert "mgmt_cli publish -s id.txt" in cli


def test_export_collect_objects_recurses_groups_and_skips_predefined():
    objdict = {
        "u-grp": {"uid": "u-grp", "name": "g", "type": "group",
                  "members": [{"uid": "u-h", "name": "h", "type": "host", "ipv4-address": "1.1.1.1"}]},
        "u-any": {"uid": "u-any", "name": "Any", "type": "CpmiAnyObject"},
    }
    by_type = mgmt_api._collect_export_objects(objdict)
    assert "host" in by_type and by_type["host"][0]["name"] == "h"   # nested member pulled up
    assert "group" in by_type
    assert "CpmiAnyObject" not in by_type                            # predefined dropped
