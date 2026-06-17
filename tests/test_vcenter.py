"""vCenter SOAP mock: method parsing, dispatch, VM enumeration, auth, and password redaction."""
import re

from app.middleware import _kind, _parse_request, _soap_op
from app.routers.datacenters import parse_vms
from app.security import hash_password
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
    # rootSnapshot is NOT a ServiceContent element — its presence broke the strict deserializer
    assert "rootSnapshot" not in xml
    # matched to a real vCenter 8.0.3 capture: version + the full manager set it returns
    assert "<version>8.0.3</version>" in xml
    assert 'type="LicenseManager">LicenseManager' in xml
    assert 'type="ScheduledTaskManager">ScheduledTaskManager' in xml


def test_login_returns_session_and_never_echoes_password():
    body = '<Body><Login xmlns="urn:vim25"><userName>admin</userName><password>s3cret</password></Login></Body>'
    xml, status, _ = vsphere.handle(DC, "Login", body)
    assert status == 200 and "<userName>admin</userName>" in xml and "<key>" in xml
    assert "s3cret" not in xml
    # UserSession has no optional fields — a strict client needs all of them present
    assert "<extensionSession>" in xml and "<ipAddress>" in xml and "<callCount>" in xml


def test_login_rejects_wrong_credentials_when_configured():
    dc = _DC("tok-auth", {"vms": [], "auth": {"username": "admin", "password_hash": hash_password("Cpwins!1")}})
    good = '<Body><Login xmlns="urn:vim25"><userName>admin</userName><password>Cpwins!1</password></Login></Body>'
    bad = '<Body><Login xmlns="urn:vim25"><userName>admin</userName><password>nope</password></Login></Body>'
    assert vsphere.handle(dc, "Login", good)[1] == 200
    xml, status, _ = vsphere.handle(dc, "Login", bad)
    assert status == 500 and "InvalidLogin" in xml          # real vCenter fault on bad creds


def test_login_permissive_without_configured_credentials():
    body = '<Body><Login xmlns="urn:vim25"><userName>x</userName><password>y</password></Login></Body>'
    xml, status, _ = vsphere.handle(DC, "Login", body)       # DC has no auth -> open lab
    assert status == 200 and "LoginResponse" in xml


def test_retrieve_properties_enumerates_every_vm():
    xml, status, _ = vsphere.handle(DC, "RetrievePropertiesEx", b"")
    assert status == 200
    assert 'type="VirtualMachine">vm-1' in xml and xml.count("<obj ") == 2
    assert "web-1" in xml and "10.0.0.11" in xml
    assert "poweredOn" in xml and "poweredOff" in xml


def test_propertycollector_workflow_enumerates_full_inventory():
    # CloudGuard's real path: CreateContainerView -> CreateFilter -> WaitForUpdatesEx.
    assert 'type="ContainerView"' in vsphere.handle(DC, "CreateContainerView", b"<x/>")[0]
    assert 'type="PropertyFilter"' in vsphere.handle(DC, "CreateFilter", b"<x/>")[0]
    # first WaitForUpdatesEx (no version) -> the FULL inventory tree, not just VMs
    xml, status, _ = vsphere.handle(DC, "WaitForUpdatesEx", b"<WaitForUpdatesEx></WaitForUpdatesEx>")
    assert status == 200
    for motype in ("Datacenter", "Folder", "ClusterComputeResource", "HostSystem",
                   "ResourcePool", "VirtualMachine"):
        assert f'type="{motype}"' in xml, motype
    # containers + 2 hosts + 2 vms all arrive as 'enter' updates
    assert xml.count("<kind>enter</kind>") == 10
    # children precede parents so the scanner resolves downward refs against already-seen objects
    assert xml.index('<obj type="Datacenter">datacenter-2') < xml.index('<obj type="Folder">group-d1')
    assert xml.index('<obj type="VirtualMachine">vm-1') < xml.index('<obj type="Folder">group-v22')
    # VMs carry name/IP and are parented under the vm folder; tree refs present
    assert 'type="VirtualMachine">vm-1' in xml and "web-1" in xml and "10.0.0.11" in xml
    assert "<name>vmFolder</name>" in xml and "<name>childEntity</name>" in xml
    assert "ArrayOfManagedObjectReference" in xml
    # the property set mirrors CloudGuard's CreateFilter propSet EXACTLY (all=false):
    # the requested ones are present...
    for prop in ("guest.ipAddress", "config.instanceUuid", "childType", "networkFolder", "hostFolder"):
        assert f"<name>{prop}</name>" in xml, prop
    # ...and properties it did NOT request are absent (extras make the strict client drop objects)
    for extra in ("runtime.powerState", "config.uuid", "guest.hostName", "config.guestFullName"):
        assert extra not in xml, extra
    # real vCenter version semantics: the mock issues an inventory-derived token
    version = re.search(r"<version>(.*?)</version>", xml).group(1)
    # echoing that exact token -> no further updates (steady state)
    held = f"<WaitForUpdatesEx><version>{version}</version></WaitForUpdatesEx>".encode()
    hx, hs, _ = vsphere.handle(DC, "WaitForUpdatesEx", held)
    assert hs == 200 and "<kind>enter</kind>" not in hx
    # a STALE/foreign version (e.g. one cached from a prior collector) -> InvalidCollectorVersion
    # fault, which makes the controller reset to an empty version for a clean initial sync
    sx, ss, _ = vsphere.handle(DC, "WaitForUpdatesEx", b"<WaitForUpdatesEx><version>1</version></WaitForUpdatesEx>")
    assert ss == 500 and "InvalidCollectorVersion" in sx
    # cleanup methods are void 200s, not faults
    assert vsphere.handle(DC, "DestroyPropertyFilter", b"<x/>")[1] == 200


def test_tag_catalog_from_vm_tags():
    cat = vsphere.tag_catalog(DC)
    assert cat["category"]["name"] == "CloudGuard"
    assert cat["category"]["associable_types"] == ["VirtualMachine"]
    names = [t["name"] for t in cat["tags"]]
    assert names == ["web"]                              # only web-1 carries a tag
    web = next(t for t in cat["tags"] if t["name"] == "web")
    assert web["category_id"] == cat["category"]["id"]
    assert cat["assoc"][web["id"]] == ["vm-1"]           # associated to web-1 (vm-1) only


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


def test_rest_basic_creds_decoding():
    import base64

    from app.routers.vcenter_mock import _basic_creds

    class _R:
        def __init__(self, h):
            self.headers = {"authorization": h}

    assert _basic_creds(_R("Basic " + base64.b64encode(b"admin:pw!1").decode())) == ("admin", "pw!1")
    assert _basic_creds(_R("")) == ("", "")


def test_soap_op_labels_sdk_calls():
    assert _soap_op("/sdk", b'<soap:Envelope><soap:Body><RetrieveServiceContent xmlns="urn:vim25">x') == "RetrieveServiceContent"
    assert _soap_op("/vcenter/tok/sdk", b"<Body><Login><userName>a</userName>") == "Login"
    assert _soap_op("/openstack/x/v3/auth/tokens", b"{}") == ""   # non-/sdk -> no SOAP op


def test_middleware_classifies_and_redacts_vcenter_soap():
    assert _kind("/vcenter/tok/sdk") == "datacenter"
    soap = b'<Envelope><Body><Login><userName>admin</userName><password>topsecret</password></Login></Body></Envelope>'
    parsed = _parse_request(soap, "text/xml; charset=utf-8")
    assert "topsecret" not in parsed and "***" in parsed and "admin" in parsed
