"""Coverage matrix: structure + that `exported` flags are derived from the live exporter specs."""
from app.services import coverage, mgmt_export


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
