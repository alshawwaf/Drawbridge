"""Cisco ACI / APIC mock: class queries (Tenant/AP/EPG/ESG/endpoints), DN hierarchy, login auth."""
from app.middleware import _kind
from app.routers.datacenters import parse_aci_groups
from app.security import hash_password
from app.services import aci


class _DC:
    def __init__(self, token, content):
        self.token = token
        self.content = content


DC = _DC("tok-aci", {
    "tenant": "DCSIM", "app_profile": "DCSIM-AP",
    "epgs": [{"name": "web-epg", "ips": ["10.30.0.11", "10.30.0.12"]},
             {"name": "db-epg", "ips": ["10.30.0.31"]}],
    "esgs": [{"name": "prod-esg", "ips": ["10.30.0.11", "10.30.0.31"]}],
})


def test_imdata_envelope():
    assert aci.imdata([{"x": 1}]) == {"totalCount": "1", "imdata": [{"x": 1}]}


def test_class_query_tenant_and_app_profile():
    t = aci.class_query(DC, "fvTenant.json")["imdata"][0]["fvTenant"]["attributes"]
    assert t["dn"] == "uni/tn-DCSIM" and t["name"] == "DCSIM"
    ap = aci.class_query(DC, "fvAp")["imdata"][0]["fvAp"]["attributes"]
    assert ap["dn"] == "uni/tn-DCSIM/ap-DCSIM-AP"


def test_class_query_epgs():
    epgs = [m["fvAEPg"]["attributes"] for m in aci.class_query(DC, "fvAEPg.json")["imdata"]]
    assert {e["name"] for e in epgs} == {"web-epg", "db-epg"}
    assert any(e["dn"] == "uni/tn-DCSIM/ap-DCSIM-AP/epg-web-epg" for e in epgs)


def test_class_query_endpoints_carry_ip_under_their_epg():
    ceps = [m["fvCEp"]["attributes"] for m in aci.class_query(DC, "fvCEp")["imdata"]]
    assert len(ceps) == 3                                              # 2 (web) + 1 (db)
    web = next(c for c in ceps if c["ip"] == "10.30.0.11")
    assert web["dn"].startswith("uni/tn-DCSIM/ap-DCSIM-AP/epg-web-epg/cep-") and web["mac"]


def test_class_query_esgs_carry_ip_selectors():
    esg = aci.class_query(DC, "fvESg")["imdata"][0]["fvESg"]
    assert esg["attributes"]["dn"] == "uni/tn-DCSIM/ap-DCSIM-AP/esg-prod-esg"
    exprs = [c["fvEPSelector"]["attributes"]["matchExpression"] for c in esg["children"]]
    assert "ip=='10.30.0.11'" in exprs and "ip=='10.30.0.31'" in exprs


def test_unknown_class_is_empty_imdata():
    assert aci.class_query(DC, "l2extOut")["imdata"] == []
    assert aci.class_query(DC, "fvWhatever")["imdata"] == []


def test_to_xml_is_the_apic_imdata_format():
    # CloudGuard's APIC client unmarshals XML — JSON makes it fail ("Content is not allowed in prolog").
    xml = aci.to_xml(aci.class_objects(DC, "fvTenant.xml"))
    assert xml.startswith("<?xml") and '<imdata totalCount="1">' in xml
    assert '<fvTenant dn="uni/tn-DCSIM" name="DCSIM"' in xml and xml.rstrip().endswith("</imdata>")
    # nested children (ESG → fvEPSelector) render as nested elements
    esg_xml = aci.to_xml(aci.class_objects(DC, "fvESg"))
    assert "<fvESg " in esg_xml and "<fvEPSelector " in esg_xml


def test_login_returns_token_and_auth_validates_when_configured():
    tok, body = aci.login_response("admin")
    assert body["imdata"][0]["aaaLogin"]["attributes"]["token"] == tok
    secured = _DC("a", {"auth": {"username": "admin", "password_hash": hash_password("c1sco!")}})
    assert aci.auth_ok(secured, "admin", "c1sco!") is True
    assert aci.auth_ok(secured, "admin", "bad") is False
    assert aci.auth_ok(DC, "anyone", "anything") is True              # open lab
    assert aci.authorized(secured, apic_cookie="abc") is True         # cookie we issued
    assert aci.authorized(secured) is False                           # configured, no cookie
    assert aci.authorized(DC) is True                                 # open lab


def test_parse_aci_groups():
    out = parse_aci_groups("web-epg = 10.30.0.11, 10.30.0.12\ndb-epg = 10.30.0.31")
    assert out == [{"name": "web-epg", "ips": ["10.30.0.11", "10.30.0.12"]},
                   {"name": "db-epg", "ips": ["10.30.0.31"]}]


def test_middleware_classifies_aci_as_datacenter():
    assert _kind("/aci/tok/api/node/class/fvTenant.json") == "datacenter"
    # CloudGuard strips the path → apex /api/aaaLogin + class queries must classify as Data Center too
    assert _kind("/api/aaaLogin.xml") == "datacenter"
    assert _kind("/api/node/class/fvTenant.xml") == "datacenter"
    # and must NOT steal the NSX-T family's apex paths
    assert _kind("/api/session/create") == "datacenter"  # still datacenter (NSX-T), not mis-routed
