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
    assert f["groups"]["tf"] is False and f["groups"]["ansible"] is True   # documented TF field gap
    assert f["ip-address"]["tf"] is False                       # TF uses ipv4/ipv6 split
    assert f["set-if-exists"]["request_only"] is True           # request flag, excluded from the diff
    assert next(o for o in mg["objects"] if o["name"] == "service-gtp")["ansible"] is None  # Ansible gap
    ga = json.load(open(os.path.join(_ART, "gaia-v1.8.json")))
    assert ga["object_count"] == len(ga["objects"]) >= 100


def test_versions_and_latest():
    v = coverage.versions()
    assert "v2.0.1" in v.get("management", []) and "v1.8" in v.get("gaia", [])
    assert coverage.latest("management") == "v2.0.1"


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
    assert fmap["groups"]["tf"] is False and fmap["ip-address"]["tf"] is False
    ex = d["examples"]
    assert set(ex) == {"web_api", "mgmt_cli", "terraform", "ansible"}
    assert ex["web_api"].startswith("POST /web_api/add-host")    # web_api JSON form
    assert "mgmt_cli add host" in ex["mgmt_cli"]
    assert 'resource "checkpoint_management_host" "example"' in ex["terraform"]
    assert "name =" in ex["terraform"] and "groups" not in ex["terraform"]   # TF-omitted field skipped
    assert "cp_mgmt_host:" in ex["ansible"]


def test_object_detail_unknown_object():
    assert "error" in coverage.object_detail("management", "v2.0.1", "does-not-exist")
