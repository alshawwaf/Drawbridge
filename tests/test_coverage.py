"""Coverage matrix: structure + that `exported` flags are derived from the live exporter specs."""
import json
import os

from app.services import coverage, mgmt_export

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


def _find(groups, name):
    for g in groups:
        for r in g["rows"]:
            if r["name"] == name:
                return r
    return None


def test_build_shape():
    data = coverage.build()
    assert data["mgmt"] and data["gaia"]
    assert data["mgmt_field_gaps"] and data["gaia_field_gaps"]
    for g in data["mgmt"] + data["gaia"]:
        assert g["total"] == len(g["rows"]) and 0 <= g["covered"] <= g["total"]


def test_exported_flag_tracks_specs():
    data = coverage.build()
    # a type the exporter handles vs one it doesn't — flag derived from mgmt_export.OBJ_SPECS
    assert _find(data["mgmt"], "host")["exported"] is True
    assert "host" in mgmt_export.OBJ_SPECS                      # the source of truth
    assert _find(data["mgmt"], "nat-rule")["exported"] is False
    assert _find(data["mgmt"], "access-rule")["exported"] is True   # rulebase is exported


def test_tool_gaps_are_marked():
    data = coverage.build()
    assert _find(data["mgmt"], "service-gtp")["ans"] is None        # Ansible gap
    assert _find(data["mgmt"], "service-gtp")["tf"] is not None
    assert _find(data["gaia"], "lldp")["ans"] is None               # Ansible gap (Gaia)
    hosts = _find(data["gaia"], "static /etc/hosts entries")
    assert hosts["api"] is None and hosts["tf"] is None and hosts["ans"] is None   # missing everywhere
