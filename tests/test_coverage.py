"""Coverage: bundled spec artifacts + the artifact-driven service (object groups, detail, examples)."""
import json
import os

from app.services import coverage

_ART = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "coverage_data")


def test_generated_coverage_artifacts_are_complete_and_shaped():
    """The bundled, spec-generated artifacts list every object with full fields + a web_api example
    + per-field 3-way support flags."""
    mg = json.load(open(os.path.join(_ART, "management-v2.0.1.json")))
    assert mg["object_count"] == len(mg["objects"]) >= 100      # all add-* objects, not a subset
    host = next(o for o in mg["objects"] if o["name"] == "host")
    assert host["terraform"] == "checkpoint_management_host" and host["ansible"] == "cp_mgmt_host"
    assert host["example"].get("name")                          # web_api JSON example present
    f = {x["name"]: x for x in host["fields"]}
    assert f["groups"]["tf"] is False and f["groups"]["tf_name"] is None and f["groups"]["ansible"] is True
    assert f["ip-address"]["tf"] is True and f["ip-address"]["tf_name"] == "ipv4_address"  # renamed, NOT a gap
    assert f["set-if-exists"]["request_only"] is True           # request flag, excluded from the diff
    assert next(o for o in mg["objects"] if o["name"] == "service-gtp")["ansible"] is None  # Ansible gap
    ga = json.load(open(os.path.join(_ART, "gaia-v1.8.json")))
    assert ga["object_count"] == len(ga["objects"]) >= 100


def test_versions_and_latest():
    v = coverage.versions()
    assert {"v2.1", "v2.0.1"} <= set(v.get("management", []))
    assert {"v1.9", "v1.8"} <= set(v.get("gaia", []))
    assert coverage.latest("management") == "v2.1" and coverage.latest("gaia") == "v1.9"


def test_object_groups_categorise_and_flag_gaps():
    groups = coverage.object_groups("management", "v2.0.1")
    titles = {g["title"] for g in groups}
    assert {"Network objects", "Services", "Access policy"} <= titles
    rows = {r["name"]: r for g in groups for r in g["rows"]}
    assert rows["host"]["has_tf"] and rows["host"]["has_ansible"]
    assert rows["service-gtp"]["has_ansible"] is False          # the Ansible gap shows at object level


def test_object_detail_has_field_diff_and_four_examples():
    d = coverage.object_detail("management", "v2.0.1", "host")
    assert d["name"] == "host"
    fmap = {f["name"]: f for f in d["fields"]}
    assert fmap["groups"]["tf"] is False                         # genuine TF gap
    assert fmap["ip-address"]["tf"] is True and fmap["ip-address"]["tf_name"] == "ipv4_address"  # renamed
    ex = d["examples"]
    assert set(ex) == {"web_api", "mgmt_cli", "terraform", "ansible"}
    assert ex["web_api"].startswith("POST /web_api/add-host")    # web_api JSON form
    assert "mgmt_cli add host" in ex["mgmt_cli"]
    assert 'resource "checkpoint_management_host" "example"' in ex["terraform"]
    assert "ipv4_address =" in ex["terraform"] and "groups" not in ex["terraform"]  # rename mapped; real gap skipped
    assert "cp_mgmt_host:" in ex["ansible"]


def test_object_detail_unknown_object():
    assert "error" in coverage.object_detail("management", "v2.0.1", "does-not-exist")


def test_gaia_examples_use_gaia_api_path_and_no_mgmt_cli():
    """Gaia must use /gaia_api/, drop the (Management-only) mgmt_cli form, and link docs."""
    d = coverage.object_detail("gaia", "v1.8", "dns")
    ex = d["examples"]
    assert ex["web_api"].startswith("POST /gaia_api/set-dns")     # NOT /web_api/
    assert "mgmt_cli" not in ex                                    # clish, not mgmt_cli — so omitted here
    assert 'context = "gaia_api"' in ex["terraform"]
    assert "check_point.gaia.cp_gaia_dns" in ex["ansible"]
    assert d["docs"]["terraform"].endswith("/resources/gaia_dns")
    assert "check_point/gaia/cp_gaia_dns_module.html" in d["docs"]["ansible"]


def test_gaia_object_level_ansible_gaps_are_accurate():
    """Routing / arp / lldp / dhcp6 have no cp_gaia_* module → Ansible gap; alias-interface has one."""
    groups = coverage.object_groups("gaia", "v1.8")
    rows = {r["name"]: r for g in groups for r in g["rows"]}
    assert rows["alias-interface"]["has_ansible"] is True
    for missing in ("bgp-external-peer", "arp", "lldp"):
        if missing in rows:
            assert rows[missing]["has_ansible"] is False
    # name exception: API `radius` → Ansible module cp_gaia_radius_server
    assert coverage.object_detail("gaia", "v1.8", "radius")["ansible"] == "cp_gaia_radius_server"


# --- generator core + check-for-updates -------------------------------------------------------

_SYNTH_SPEC = {
    "openapi": "3.0.0", "info": {"version": "2.0.1"},
    "paths": {"/add-host": {"post": {"requestBody": {"content": {"application/json": {"schema": {
        "type": "object", "required": ["name"], "properties": {
            "name": {"type": "string"},
            "ip-address": {"type": "string"},
            "groups": {"type": "array", "items": {"type": "string"}},
            "color": {"type": "string", "enum": ["black", "red"]},
            "ignore-warnings": {"type": "boolean"}}}}}}}}},
}


def test_build_from_spec_shapes_objects_fields_and_example():
    from app.services import coverage_build as cb
    art = cb.build_from_spec("management", "vtest", _SYNTH_SPEC)
    assert art["object_count"] == 1
    o = art["objects"][0]
    assert o["name"] == "host" and o["terraform"] == "checkpoint_management_host" and o["ansible"] == "cp_mgmt_host"
    fm = {f["name"]: f for f in o["fields"]}
    assert fm["groups"]["tf"] is False and fm["groups"]["tf_name"] is None and fm["groups"]["ansible"] is True
    assert fm["ip-address"]["tf_name"] == "ipv4_address"   # generic API field → renamed TF arg, still supported
    assert fm["ignore-warnings"]["request_only"] is True
    assert o["example"]["color"] == "black"               # enum[0]
    assert "ignore-warnings" not in o["example"]           # request-only excluded from the body


def test_check_for_update_fetch_error_is_graceful(monkeypatch):
    from app.services import coverage_build as cb

    def boom(*a, **k):
        raise RuntimeError("offline")
    monkeypatch.setattr(cb, "fetch_spec", boom)
    r = cb.check_for_update("management")
    assert r["ok"] is False and "offline" in r["error"]


def test_check_for_update_adds_then_finds_existing(monkeypatch, tmp_path):
    from app.services import coverage_build as cb
    monkeypatch.setattr(cb, "OUT_DIR", str(tmp_path))
    monkeypatch.setattr(cb, "fetch_spec", lambda api, version="": _SYNTH_SPEC)
    r = cb.check_for_update("management", "v9.9-test")
    assert r["ok"] and r["added"] and r["version"] == "v9.9-test" and r["object_count"] == 1
    assert (tmp_path / "management-v9.9-test.json").exists()
    r2 = cb.check_for_update("management", "v9.9-test")    # now bundled
    assert r2["ok"] and r2["added"] is False
