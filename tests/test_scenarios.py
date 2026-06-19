"""Live-mutation primitives — provider-aware tag/workload edits + snapshot/restore (pure functions)."""
import pytest

from app.services import scenarios


def test_list_tag_provider_add_remove():
    content = {"vms": [{"name": "web-1", "ip": "10.0.0.11", "tags": ["prod"]}]}
    c, desc = scenarios.add_tag("vcenter", content, "web-1", "web")
    assert c["vms"][0]["tags"] == ["prod", "web"] and "web" in desc
    assert content["vms"][0]["tags"] == ["prod"]            # original untouched (pure)
    c2, _ = scenarios.add_tag("vcenter", c, "web-1", "web")  # idempotent
    assert c2["vms"][0]["tags"] == ["prod", "web"]
    c3, _ = scenarios.remove_tag("vcenter", c, "web-1", "prod")
    assert c3["vms"][0]["tags"] == ["web"]


def test_dict_tag_providers():
    k8s = {"pods": [{"namespace": "default", "name": "p1", "ip": "10.40.1.1", "labels": {"app": "web"}}]}
    c, _ = scenarios.add_tag("kubernetes", k8s, "p1", "tier=frontend")
    assert c["pods"][0]["labels"] == {"app": "web", "tier": "frontend"}
    c2, _ = scenarios.remove_tag("kubernetes", c, "p1", "app")    # key-only removal
    assert c2["pods"][0]["labels"] == {"tier": "frontend"}
    ntx = {"vms": [{"name": "vm1", "ip": "10.50.0.1", "categories": {}}]}
    c3, _ = scenarios.add_tag("nutanix", ntx, "vm1", "Environment=Production")
    assert c3["vms"][0]["categories"] == {"Environment": "Production"}
    with pytest.raises(ValueError):                              # dict tag needs key=value
        scenarios.add_tag("nutanix", ntx, "vm1", "bareword")


def test_add_remove_workload_uses_provider_key_and_tag_style():
    osc = {"instances": [{"name": "i-1", "ip": "10.0.0.5", "tags": []}]}
    c, desc = scenarios.add_workload("openstack", osc, "i-2", "10.0.0.6", tags=["web", "prod"])
    assert [i["name"] for i in c["instances"]] == ["i-1", "i-2"]
    assert c["instances"][1]["tags"] == ["web", "prod"] and "i-2" in desc
    k8s, _ = scenarios.add_workload("kubernetes", {"pods": []}, "p9", "10.40.9.9", tags=["app=api"])
    assert k8s["pods"][0]["labels"] == {"app": "api"} and k8s["pods"][0]["namespace"] == "default"
    back, _ = scenarios.remove_workload("openstack", c, "i-2")
    assert [i["name"] for i in back["instances"]] == ["i-1"]


def test_errors():
    with pytest.raises(ValueError):
        scenarios.add_tag("vcenter", {"vms": []}, "nope", "x")          # missing workload
    with pytest.raises(ValueError):
        scenarios.add_tag("aci", {}, "x", "y")                          # provider not taggable
    with pytest.raises(ValueError):
        scenarios.remove_workload("vcenter", {"vms": []}, "ghost")      # missing workload
    with pytest.raises(ValueError):
        scenarios.add_workload("vcenter", {"vms": [{"name": "dup"}]}, "dup", "1.1.1.1")  # duplicate


def test_snapshot_restore_roundtrip():
    content = {"vms": [{"name": "a", "tags": ["x"]}]}
    snap = scenarios.snapshot(content)
    mutated, _ = scenarios.add_tag("nsxt", content, "a", "y")
    assert mutated["vms"][0]["tags"] == ["x", "y"]
    assert snap == {"vms": [{"name": "a", "tags": ["x"]}]}              # snapshot frozen
    restored = scenarios.restore(snap)
    assert restored == snap and restored is not snap                   # deep copy


def test_helpers():
    assert scenarios.workload_key("kubernetes") == "pods"
    assert scenarios.workload_key("openstack") == "instances"
    assert scenarios.supports_tags("vcenter") and not scenarios.supports_tags("aci")
    assert scenarios.workload_names("vcenter", {"vms": [{"name": "a"}, {"name": "b"}]}) == ["a", "b"]


def test_tag_field_and_map_flags():
    assert scenarios.tag_field("vcenter") == "tags" and not scenarios.is_map_tags("vcenter")
    assert scenarios.tag_field("kubernetes") == "labels" and scenarios.is_map_tags("kubernetes")
    assert scenarios.tag_field("nutanix") == "categories" and scenarios.is_map_tags("nutanix")
    assert scenarios.tag_field("aci") is None and not scenarios.is_map_tags("aci")


def test_every_preset_has_a_talk_track_guide():
    guides = scenarios.preset_guides()
    # Every preset must ship a talk-track so the Scenarios demo guide never renders empty.
    for key in scenarios._PRESET_LABELS:
        assert key in guides, f"preset {key!r} has no talk-track guide"
        assert guides[key].get("story") and guides[key].get("watch"), key


def test_workloads_reads_provider_specific_key():
    content = {"vms": [{"name": "v"}], "instances": [{"name": "i"}], "pods": [{"name": "p"}]}
    assert scenarios.workloads("vcenter", content) == [{"name": "v"}]
    assert scenarios.workloads("openstack", content) == [{"name": "i"}]
    assert scenarios.workloads("kubernetes", content) == [{"name": "p"}]
    assert scenarios.workloads("aci", {}) == []                     # no 'vms' key → empty, not a crash


def test_apply_action_dispatch():
    c = {"vms": [{"name": "a", "ip": "10.0.0.1", "tags": []}]}
    c1, _ = scenarios.apply_action("vcenter", c, "add_tag", name="a", value="prod")
    assert c1["vms"][0]["tags"] == ["prod"]
    c2, _ = scenarios.apply_action("vcenter", c, "add_workload", name="b", ip="10.0.0.2", value="web")
    assert {w["name"] for w in c2["vms"]} == {"a", "b"} and c2["vms"][1]["tags"] == ["web"]
    c3, _ = scenarios.apply_action("vcenter", c2, "remove_workload", name="a")
    assert [w["name"] for w in c3["vms"]] == ["b"]
    with pytest.raises(ValueError):
        scenarios.apply_action("vcenter", c, "frobnicate", name="a")


def test_plan_preset_quarantine_and_blocklist():
    vc = {"vms": [{"name": "web-1", "ip": "10.0.0.11", "tags": []},
                  {"name": "web-2", "ip": "10.0.0.12", "tags": []}]}
    _, steps = scenarios.plan_preset("quarantine", "vcenter", vc)
    assert steps == [{"action": "add_tag", "name": "web-1", "value": "quarantine",
                      "desc": "quarantine web-1"}]                          # first workload only
    _, bsteps = scenarios.plan_preset("blocklist", "vcenter", vc)
    assert [s["name"] for s in bsteps] == ["web-1", "web-2"]                # every workload
    assert all(s["value"] == "blocklist" for s in bsteps)
    k8s = {"pods": [{"name": "p1", "ip": "10.40.0.1", "labels": {}}]}
    _, ksteps = scenarios.plan_preset("quarantine", "kubernetes", k8s)
    assert ksteps[0]["value"] == "quarantine=true"                         # map providers: key=value
    with pytest.raises(ValueError):
        scenarios.plan_preset("quarantine", "vcenter", {"vms": []})        # nothing to quarantine
    with pytest.raises(ValueError):
        scenarios.plan_preset("quarantine", "aci", {})                     # provider not taggable


def test_plan_preset_scale_out_generates_unique_targets():
    vc = {"vms": [{"name": "vm-scaleout-1", "ip": "10.0.0.201", "tags": []}]}   # force collisions
    _, steps = scenarios.plan_preset("scale_out", "vcenter", vc)
    names = [s["name"] for s in steps]
    ips = [s["ip"] for s in steps]
    assert len(steps) == 3 and all(s["action"] == "add_workload" for s in steps)
    assert "vm-scaleout-1" not in names and len(set(names)) == 3            # skips existing name
    assert "10.0.0.201" not in ips and len(set(ips)) == 3                   # skips existing ip
    assert all(ip.startswith("10.0.0.") for ip in ips)                     # same /24 as inventory
    assert all(s["value"] == "scaleout" for s in steps)
    _, empty = scenarios.plan_preset("scale_out", "openstack", {})         # works on empty inventory
    assert [s["name"] for s in empty] == \
        ["instance-scaleout-1", "instance-scaleout-2", "instance-scaleout-3"]
    assert all(s["ip"].startswith("10.99.0.") for s in empty)              # default subnet


def test_list_presets_gating():
    assert scenarios.list_presets("aci", {}) == []                         # not taggable → none
    full = {p["key"]: p["count"] for p in scenarios.list_presets("vcenter", {"vms": [{"name": "a", "ip": "1.1.1.1"}]})}
    assert full == {"quarantine": 1, "scale_out": 3, "blocklist": 1}
    empty = {p["key"]: p["count"] for p in scenarios.list_presets("vcenter", {"vms": []})}
    assert empty == {"quarantine": 0, "scale_out": 3, "blocklist": 0}      # only scale-out runnable


def test_scenarios_routes_registered():
    from app.main import create_app

    def paths(router):
        for r in router.routes:
            if hasattr(r, "original_router"):          # included sub-router wrapper
                yield from paths(r.original_router)
            elif getattr(r, "path", None):
                yield r.path

    registered = set(paths(create_app()))
    assert {"/scenarios", "/scenarios/{dc_id}/mutate",
            "/scenarios/{dc_id}/set-baseline", "/scenarios/{dc_id}/reset",
            "/scenarios/{dc_id}/run", "/scenarios/{dc_id}/stop",
            "/scenarios/{dc_id}/run-status"} <= registered
