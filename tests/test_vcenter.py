"""vCenter SOAP mock: method parsing, dispatch, VM enumeration, and password redaction."""
from app.middleware import _kind, _parse_request
from app.routers.datacenters import parse_vms
from app.services import vsphere


class _DC:
    def __init__(self, token, content):
        self.token = token
        self.content = content


DC = _DC("tok-vc", {"vms": [
    {"name": "web-1", "ip": "10.0.0.11", "tags": ["web"], "power": "poweredOn"},
    {"name": "db-1", "ip": "10.0.0.21", "tags": [], "power": "poweredOff"},
]})


def test_parse_method_from_soap_body():
    body = ('<soapenv:Envelope xmlns:soapenv="x"><soapenv:Body>'
            '<RetrieveServiceContent xmlns="urn:vim25">'
            '<_this type="ServiceInstance">ServiceInstance</_this>'
            "</RetrieveServiceContent></soapenv:Body></soapenv:Envelope>")
    assert vsphere.parse_method(body) == "RetrieveServiceContent"
    assert vsphere.parse_method(b"<Body><Login>x") == "Login"
    assert vsphere.parse_method("not soap") == ""


def test_service_content_advertises_virtualcenter():
    xml, status, method = vsphere.handle(DC, "RetrieveServiceContent", b"")
    assert status == 200 and method == "RetrieveServiceContent"
    assert "<apiType>VirtualCenter</apiType>" in xml
    assert 'type="SessionManager">SessionManager' in xml


def test_login_returns_session_and_never_echoes_password():
    body = '<Body><Login xmlns="urn:vim25"><userName>admin</userName><password>s3cret</password></Login></Body>'
    xml, status, _ = vsphere.handle(DC, "Login", body)
    assert status == 200 and "<userName>admin</userName>" in xml and "<key>" in xml
    assert "s3cret" not in xml


def test_retrieve_properties_enumerates_every_vm():
    xml, status, _ = vsphere.handle(DC, "RetrievePropertiesEx", b"")
    assert status == 200
    assert 'type="VirtualMachine">vm-1' in xml and xml.count("<obj ") == 2
    assert "web-1" in xml and "10.0.0.11" in xml
    assert "poweredOn" in xml and "poweredOff" in xml


def test_unknown_method_returns_soap_fault():
    xml, status, _ = vsphere.handle(DC, "RebootHost_Task", b"")
    assert status == 500 and "Fault" in xml and "not modelled" in xml


def test_logout_and_current_time():
    assert "LogoutResponse" in vsphere.handle(DC, "Logout", b"")[0]
    assert "CurrentTimeResponse" in vsphere.handle(DC, "CurrentTime", b"")[0]


def test_parse_vms_quick_entry():
    out = parse_vms("web-1 = 10.0.0.11 | web, prod\ndb-1 = 10.0.0.21")
    assert out[0] == {"name": "web-1", "ip": "10.0.0.11", "tags": ["web", "prod"],
                      "power": "poweredOn", "guest_os": ""}
    assert out[1]["name"] == "db-1" and out[1]["tags"] == []


def test_middleware_classifies_and_redacts_vcenter_soap():
    assert _kind("/vcenter/tok/sdk") == "datacenter"
    soap = b'<Envelope><Body><Login><userName>admin</userName><password>topsecret</password></Login></Body></Envelope>'
    parsed = _parse_request(soap, "text/xml; charset=utf-8")
    assert "topsecret" not in parsed and "***" in parsed and "admin" in parsed
