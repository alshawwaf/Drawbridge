"""Nutanix Prism mock: v3 (POST) + v4 (GET) VMs/categories, VM↔category query, Basic auth."""
import base64

from app.middleware import _kind
from app.routers.datacenters import parse_nutanix_vms
from app.security import hash_password
from app.services import nutanix


class _DC:
    def __init__(self, content):
        self.token = "tok-ntnx"
        self.content = content


DC = _DC({"vms": [
    {"name": "web-1", "ip": "10.50.0.11", "categories": {"Environment": "Production", "AppType": "Web"}},
    {"name": "web-2", "ip": "10.50.0.12", "categories": {"Environment": "Production", "AppType": "Web"}},
    {"name": "db-1", "ip": "10.50.0.21", "categories": {"Environment": "Production", "AppType": "Database"}},
]})


def test_categories_derived_from_vms():
    cats = nutanix.categories(DC)
    assert cats["Environment"] == ["Production"]
    assert cats["AppType"] == ["Database", "Web"]            # sorted, deduped


def test_v3_vms_carry_ip_and_categories():
    ents = nutanix.vms_list_v3(DC)["entities"]
    assert len(ents) == 3
    web = next(e for e in ents if e["status"]["name"] == "web-1")
    ips = [ep["ip"] for nic in web["status"]["resources"]["nic_list"] for ep in nic["ip_endpoint_list"]]
    assert ips == ["10.50.0.11"]
    assert web["metadata"]["categories"] == {"Environment": "Production", "AppType": "Web"}


def test_v3_categories_list_is_keys():
    names = {e["name"] for e in nutanix.categories_list_v3(DC)["entities"]}
    assert names == {"Environment", "AppType"}


def test_v3_category_values():
    vals = {e["value"] for e in nutanix.category_values_v3(DC, "AppType")["entities"]}
    assert vals == {"Web", "Database"}


def test_v3_category_query_resolves_vms_by_tag():
    body = {"category_filter": {"params": {"AppType": ["Web"]}}}
    res = nutanix.category_query_v3(DC, body)["results"][0]["kind_reference_list"]
    assert {r["name"] for r in res} == {"web-1", "web-2"}    # only the Web VMs, not db-1


def test_v4_vms_learned_ips_and_category_refs():
    data = nutanix.vms_list_v4(DC)["data"]
    web = next(v for v in data if v["name"] == "web-1")
    learned = [a["value"] for n in web["nics"] for a in n["networkInfo"]["ipv4Info"]["learnedIpAddresses"]]
    assert learned == ["10.50.0.11"] and len(web["categories"]) == 2


def test_v4_categories_are_key_value_pairs():
    data = nutanix.categories_list_v4(DC)["data"]
    pairs = {(c["key"], c["value"]) for c in data}
    assert ("Environment", "Production") in pairs and ("AppType", "Web") in pairs
    assert all("extId" in c for c in data)


def test_v4_envelope_has_metadata():
    m = nutanix.vms_list_v4(DC)["metadata"]
    assert m["totalAvailableResults"] == 3 and m["hasMorePages"] is False


def test_basic_auth():
    secured = _DC({"auth": {"username": "admin", "password_hash": hash_password("nutanix/4u")},
                   "vms": []})
    ok = "Basic " + base64.b64encode(b"admin:nutanix/4u").decode()
    bad = "Basic " + base64.b64encode(b"admin:wrong").decode()
    assert nutanix.auth_ok(secured, ok) is True
    assert nutanix.auth_ok(secured, bad) is False
    assert nutanix.auth_ok(secured, "") is False
    assert nutanix.auth_ok(DC, "anything") is True          # open lab


def test_parse_nutanix_vms():
    vms = parse_nutanix_vms("web-1 = 10.50.0.11 | Environment=Production, AppType=Web\ndb-1 = 10.50.0.21")
    assert vms[0] == {"name": "web-1", "ip": "10.50.0.11",
                      "categories": {"Environment": "Production", "AppType": "Web"}}
    assert vms[1]["categories"] == {}


def test_middleware_classifies_nutanix_as_datacenter():
    assert _kind("/api/nutanix/v3/vms/list") == "datacenter"
    assert _kind("/api/vmm/v4.1/ahv/config/vms") == "datacenter"
    assert _kind("/api/prism/v4.1/config/categories") == "datacenter"
    assert _kind("/nutanix/tok/api/nutanix/v3/vms/list") == "datacenter"
