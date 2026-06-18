"""NSX-T Policy Mode mock: groups, VM inventory + VIF IPs, tag-based membership, auth."""
import base64

from app.middleware import _kind
from app.routers.datacenters import parse_nsxt_groups
from app.security import hash_password
from app.services import nsxt


class _DC:
    def __init__(self, token, content):
        self.token = token
        self.content = content


DC = _DC("tok-nsx", {
    "vms": [
        {"name": "web-vm-01", "ip": "10.10.20.5", "tags": ["tier=web", "env=prod"]},
        {"name": "db-vm-01", "ip": "10.10.30.5", "tags": ["tier=db"]},
    ],
    "groups": [{"name": "Web Servers", "member_tag": "tier=web", "tags": ["env=production"]}],
})


def test_list_result_envelope():
    assert nsxt.list_result([{"a": 1}]) == {"results": [{"a": 1}], "result_count": 1}


def test_virtual_machines_carry_tags_and_external_id():
    vms = nsxt.virtual_machines(DC)["results"]
    assert {v["display_name"] for v in vms} == {"web-vm-01", "db-vm-01"}
    web = next(v for v in vms if v["display_name"] == "web-vm-01")
    assert {"scope": "tier", "tag": "web"} in web["tags"]
    assert web["resource_type"] == "VirtualMachine" and web["external_id"]


def test_vif_holds_ip_joined_by_owner_vm_id():
    vms = {v["display_name"]: v for v in nsxt.virtual_machines(DC)["results"]}
    vifs = nsxt.vifs(DC)["results"]
    web_vif = next(f for f in vifs if f["owner_vm_id"] == vms["web-vm-01"]["external_id"])
    assert web_vif["ip_address_info"][0]["ip_addresses"] == ["10.10.20.5"]


def test_groups_expose_membership_condition_and_tags():
    g = nsxt.groups(DC)["results"][0]
    assert g["display_name"] == "Web Servers" and g["resource_type"] == "Group"
    cond = g["expression"][0]
    assert cond["resource_type"] == "Condition" and cond["key"] == "Tag" and cond["value"] == "tier|web"
    assert {"scope": "env", "tag": "production"} in g["tags"]


def test_groups_carry_parent_path_to_their_domain():
    # parent_path is what makes a group nest under its domain (= Region on the Global Manager).
    g = nsxt.groups(DC)["results"][0]
    assert g["parent_path"] == "/infra/domains/default" and g["relative_path"] == "web-servers"
    gg = nsxt.groups(DC, infra="global-infra")["results"][0]
    assert gg["parent_path"] == "/global-infra/domains/default"


def test_group_members_resolve_by_tag():
    members = nsxt.group_members(DC, "web-servers")["results"]
    assert [m["display_name"] for m in members] == ["web-vm-01"]   # db-vm-01 excluded (tier=db)
    assert members[0]["resource_type"] == "RealizedVirtualMachine"


def test_group_member_ips_resolve_to_member_vm_ips():
    # CloudGuard (Policy Mode) resolves a group to IPs via .../members/ip-addresses, not VMs.
    assert nsxt.group_member_ips(DC, "web-servers")["results"] == ["10.10.20.5"]  # web-vm-01 only
    assert nsxt.group_member_ips(DC, "nope")["results"] == []


def test_auth_validates_only_when_configured():
    dc = _DC("a", {"vms": [], "auth": {"username": "ops", "password_hash": hash_password("nsx!")}})
    assert nsxt.auth_ok(dc, "ops", "nsx!") is True
    assert nsxt.auth_ok(dc, "ops", "bad") is False
    assert nsxt.auth_ok(DC, "anyone", "anything") is True          # no creds = open lab


def test_authorized_basic_session_and_open():
    dc = _DC("a", {"vms": [], "auth": {"username": "ops", "password_hash": hash_password("nsx!")}})
    good = "Basic " + base64.b64encode(b"ops:nsx!").decode()
    bad = "Basic " + base64.b64encode(b"ops:wrong").decode()
    assert nsxt.authorized(dc, authorization=good) is True
    assert nsxt.authorized(dc, authorization=bad) is False
    assert nsxt.authorized(dc, jsessionid="abc") is True           # a session we issued
    assert nsxt.authorized(dc) is False                            # configured, nothing presented
    assert nsxt.authorized(DC) is True                             # open lab


def test_parse_nsxt_groups():
    out = parse_nsxt_groups("Web Servers = tier=web | env=production, app=shop\nDB = tier=db")
    assert out[0] == {"name": "Web Servers", "member_tag": "tier=web",
                      "tags": ["env=production", "app=shop"]}
    assert out[1] == {"name": "DB", "member_tag": "tier=db", "tags": []}


def test_middleware_classifies_nsxt_as_datacenter():
    assert _kind("/nsxt/tok/policy/api/v1/infra/domains/default/groups") == "datacenter"


# --- Global NSX-T (Global Manager) -----------------------------------------------------------

def test_global_groups_use_global_infra_path():
    # Local Manager (default) vs Global Manager only differ in the policy path segment.
    assert nsxt.groups(DC)["results"][0]["path"].startswith("/infra/domains/")
    g = nsxt.groups(DC, infra="global-infra")["results"][0]
    assert g["path"] == "/global-infra/domains/default/groups/web-servers"
    # the rest (membership condition, tags) is identical — same data model
    assert g["expression"][0]["value"] == "tier|web"


def test_middleware_classifies_global_manager_as_datacenter():
    assert _kind("/global-manager/api/v1/global-infra/domains/default/groups") == "datacenter"


def test_sites_returns_one_location_so_the_region_is_real():
    # /global-infra/sites must return a Location (not empty) or CloudGuard's Region stays an empty
    # placeholder and the global NS Groups never nest under it.
    s = nsxt.sites(DC)["results"]
    assert len(s) == 1
    assert s[0]["resource_type"] == "Site" and s[0]["display_name"] == "default"
    assert s[0]["path"] == "/global-infra/sites/default" and s[0]["site_type"] == "ONPREM_LM"


def test_domains_lists_the_default_domain():
    # CloudGuard enumerates /infra/domains before fetching each domain's groups (and renders each
    # global-infra domain as a Region on the Global Manager).
    d = nsxt.domains()["results"][0]
    assert d["resource_type"] == "Domain" and d["id"] == "default" and d["display_name"] == "default"
    assert d["path"] == "/infra/domains/default" and d["parent_path"] == "/infra"
    gd = nsxt.domains(infra="global-infra")["results"][0]
    assert gd["path"] == "/global-infra/domains/default" and gd["parent_path"] == "/global-infra"
