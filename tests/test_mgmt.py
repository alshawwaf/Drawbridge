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


def test_list_access_layers_reads_the_access_layers_key():
    """Regression: show-access-layers returns its list under 'access-layers', not the usual 'objects'.
    The response below has an empty 'objects' (what the old code wrongly read) and the real layers
    under 'access-layers' — the count must come from the latter."""
    s = mgmt_api.MgmtSession.__new__(mgmt_api.MgmtSession)   # skip __init__ → no real httpx client
    seen = {}

    def fake_call(command, payload=None):
        seen["command"] = command
        return {"objects": [], "access-layers": [{"name": "Network", "uid": "u1"},
                                                 {"name": "App Control", "uid": "u2"}],
                "total": 2, "to": 2}

    s.call = fake_call
    layers = s.list_access_layers()
    assert seen["command"] == "show-access-layers"
    assert [l["name"] for l in layers] == ["Network", "App Control"]


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


# --- writes: build_set_rule_op + apply_changes (Phase 4) ------------------------------------

def _fake_session(rec, fail_on=None):
    """A stand-in for MgmtSession that records calls instead of hitting a server."""
    class FS:
        def __init__(self, server, secret, timeout=30.0):
            self.trace = []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def call(self, command, payload=None):
            rec["calls"].append((command, payload))
            if fail_on and command == fail_on:
                raise mgmt_api.MgmtError("server said no")
            return {}

        def publish(self):
            rec["calls"].append(("publish", {}))

        def discard(self):
            rec["calls"].append(("discard", {}))
    return FS


def test_build_set_rule_op_only_sends_changed_fields():
    op = mgmt_api.build_set_rule_op("Network", "u-1",
                                    {"enabled": False, "action": "Drop", "track": "Log",
                                     "name": "New", "comments": "c"})
    assert op["command"] == "set-access-rule"
    p = op["payload"]
    assert p["uid"] == "u-1" and p["layer"] == "Network"
    assert p["enabled"] is False and p["action"] == "Drop"
    assert p["track"] == {"type": "Log"} and p["new-name"] == "New" and p["comments"] == "c"
    assert "disable" in op["summary"]
    # only the keys present in the change dict are sent — nothing else on the rule is touched
    assert set(mgmt_api.build_set_rule_op("Network", "u-1", {"action": "Accept"})["payload"]) == \
        {"uid", "layer", "action"}


def test_apply_changes_publishes_then_reports(monkeypatch):
    rec = {"calls": []}
    monkeypatch.setattr(mgmt_api, "MgmtSession", _fake_session(rec))
    res = mgmt_api.apply_changes(object(), "secret",
                                 [{"command": "set-access-rule", "payload": {"uid": "u"}, "summary": "e"}],
                                 publish=True)
    assert res["ok"] is True and res["published"] is True
    assert [c for c, _ in rec["calls"]] == ["set-access-rule", "publish"]


def test_apply_changes_dry_run_discards(monkeypatch):
    rec = {"calls": []}
    monkeypatch.setattr(mgmt_api, "MgmtSession", _fake_session(rec))
    res = mgmt_api.apply_changes(object(), "secret",
                                 [{"command": "set-access-rule", "payload": {}, "summary": "e"}],
                                 publish=False)
    assert res["ok"] is True and res["published"] is False
    assert [c for c, _ in rec["calls"]] == ["set-access-rule", "discard"]   # validated, never committed


def test_apply_changes_discards_on_error_never_publishes(monkeypatch):
    rec = {"calls": []}
    monkeypatch.setattr(mgmt_api, "MgmtSession", _fake_session(rec, fail_on="set-access-rule"))
    res = mgmt_api.apply_changes(object(), "secret",
                                 [{"command": "set-access-rule", "payload": {}, "summary": "e"}],
                                 publish=True)
    assert res["ok"] is False and "server said no" in res["error"]
    cmds = [c for c, _ in rec["calls"]]
    assert "publish" not in cmds and "discard" in cmds
