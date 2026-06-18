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


def test_workloads_reads_provider_specific_key():
    content = {"vms": [{"name": "v"}], "instances": [{"name": "i"}], "pods": [{"name": "p"}]}
    assert scenarios.workloads("vcenter", content) == [{"name": "v"}]
    assert scenarios.workloads("openstack", content) == [{"name": "i"}]
    assert scenarios.workloads("kubernetes", content) == [{"name": "p"}]
    assert scenarios.workloads("aci", {}) == []                     # no 'vms' key → empty, not a crash


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
            "/scenarios/{dc_id}/set-baseline", "/scenarios/{dc_id}/reset"} <= registered
