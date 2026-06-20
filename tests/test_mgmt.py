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
        # host carries the full surface: ipv4, color/comments/tags (common), and a NAT nested block
        "host": [{"uid": "u-web", "name": "web-srv", "type": "host", "ipv4-address": "10.0.0.5",
                  "color": "red", "comments": "web tier", "domain": {"domain-type": "domain"},
                  "tags": [{"name": "prod"}, {"name": "dmz"}],
                  "nat-settings": {"auto-rule": True, "method": "static", "ipv4-address": "1.2.3.4"}}],
        "network": [{"uid": "u-net", "name": "dmz-net", "type": "network",
                     "subnet4": "10.0.0.0", "mask-length4": 24, "color": "black"}],
        "group": [{"uid": "u-grp", "name": "web-grp", "type": "group", "members": [{"name": "web-srv"}]}],
        # service-tcp with a bool field + an aggressive-aging nested block
        "service-tcp": [{"uid": "u-svc", "name": "tcp-8443", "type": "service-tcp", "port": "8443",
                         "match-for-any": False,
                         "aggressive-aging": {"enable": True, "timeout": 600, "use-default-timeout": False}}],
        "vpn-community-meshed": [{"uid": "u-vpn", "name": "MyMesh", "type": "vpn-community-meshed"}],  # unsupported
    },
    "rules": [
        {"kind": "section", "name": "Web"},
        {"kind": "rule", "number": 1, "name": "Allow web", "enabled": True,
         "source": ["web-grp"], "destination": ["web-srv"], "service": ["tcp-8443"],
         "vpn": ["MyMesh"], "content": ["Credit Card Numbers"], "content_direction": "any",
         "time": ["WorkHours"], "install_on": ["gw1"], "custom_fields": {"field-1": "ticket-123"},
         "track_full": {"type": "Log", "accounting": True, "per_connection": False,
                        "per_session": False, "enable_firewall_session": False, "alert": ""},
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
    assert s["skipped"] == {"vpn-community-meshed": 1}   # unknown type counted, never crashes


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


def test_export_terraform_carries_all_supported_fields():
    """Common fields + nested blocks must round-trip into Terraform."""
    tf = mgmt_export.generate(EXPORT_BUNDLE)["terraform"]
    assert 'color = "red"' in tf and 'comments = "web tier"' in tf
    assert 'tags = ["prod", "dmz"]' in tf
    assert "nat_settings {" in tf and "auto_rule = true" in tf and 'method = "static"' in tf
    assert "aggressive_aging {" in tf and "timeout = 600" in tf and "use_default_timeout = false" in tf
    assert "match_for_any = false" in tf                # a bool that is False is still emitted


def test_export_rule_carries_all_columns():
    """A faithful rulebase backup must carry content / time / install-on / custom-fields / full track
    / vpn across all three targets."""
    art = mgmt_export.generate(EXPORT_BUNDLE)
    tf, ans, cli = art["terraform"], art["ansible"], art["mgmt_cli"]
    # Terraform
    assert 'vpn_communities = ["MyMesh"]' in tf            # TF models a community list as vpn_communities
    assert 'content = ["Credit Card Numbers"]' in tf and 'content_direction = "any"' in tf
    assert 'time = ["WorkHours"]' in tf and 'install_on = ["gw1"]' in tf
    assert "custom_fields {" in tf and 'field_1 = "ticket-123"' in tf
    assert "accounting = true" in tf                       # full track settings, not just type
    # Ansible
    assert 'vpn: ["MyMesh"]' in ans and 'content: ["Credit Card Numbers"]' in ans
    assert 'time: ["WorkHours"]' in ans and "accounting: true" in ans
    assert "custom_fields:" in ans and 'field_1: "ticket-123"' in ans
    # mgmt_cli
    assert 'content.1 "Credit Card Numbers"' in cli and 'vpn.1 "MyMesh"' in cli
    assert 'time.1 "WorkHours"' in cli and 'install-on.1 "gw1"' in cli
    assert 'custom-fields.field-1 "ticket-123"' in cli and "track-settings.accounting true" in cli


def test_export_new_object_types():
    """The object types added from the OpenAPI spec render across all three targets."""
    bundle = {"layer": "L", "rules": [], "objects_by_type": {
        "service-icmp6": [{"uid": "u1", "name": "icmp6-echo", "type": "service-icmp6",
                           "icmp-type": 128, "icmp-code": 0}],
        "application-site": [{"uid": "u2", "name": "MyApp", "type": "application-site",
                              "primary-category": "Custom", "url-list": ["x.com", "y.com"],
                              "urls-defined-as-regular-expression": False}],
        "time-group": [{"uid": "u3", "name": "WorkTimes", "type": "time-group",
                        "members": [{"name": "WorkHours"}]}],
    }}
    art = mgmt_export.generate(bundle)
    tf, ans, cli = art["terraform"], art["ansible"], art["mgmt_cli"]
    assert 'resource "checkpoint_management_service_icmp6" "icmp6_echo"' in tf and "icmp_type = 128" in tf
    assert 'resource "checkpoint_management_application_site" "myapp"' in tf
    assert 'url_list = ["x.com", "y.com"]' in tf and 'primary_category = "Custom"' in tf
    assert "check_point.mgmt.cp_mgmt_time_group:" in ans and 'mgmt_cli add application-site' in cli
    assert art["stats"]["objects"] == 3 and art["stats"]["skipped"] == {}


def test_export_predefined_objects_are_referenced_not_emitted():
    tf = mgmt_export.generate(EXPORT_BUNDLE)["terraform"]
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
    # nested NAT renders as a YAML sub-block in Ansible and dotted params in mgmt_cli
    assert "nat_settings:" in ans and "auto_rule: true" in ans
    assert 'mgmt_cli add host name "web-srv" ipv4-address "10.0.0.5"' in cli
    assert 'nat-settings.method "static"' in cli and 'tags.1 "prod"' in cli
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
