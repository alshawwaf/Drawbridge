"""Mock VMware vCenter SOAP API (vSphere Web Services) that Check Point's CloudGuard Controller
connects to.

CloudGuard's vCenter Data Center object connects to ``<portal>/vcenter/<token>/sdk`` and speaks
the vSphere SOAP API. The usual sequence is:

    GET  /sdk/vimServiceVersions.xml          (version negotiation)
    POST /sdk  RetrieveServiceContent          -> managers (sessionManager, propertyCollector, ...)
    POST /sdk  Login (SessionManager)          -> a UserSession
    POST /sdk  RetrieveProperties[Ex]          -> enumerate VirtualMachine objects + properties
    POST /sdk  Logout

We build best-effort SOAP responses for these. The exact PropertyCollector spec CloudGuard sends
isn't publicly documented, so every request is logged (Activity log) and the VM enumeration is
refined to match what the controller actually asks for. No real vCenter is involved.
"""
import datetime as dt
import re
import uuid

VIM_NS = "urn:vim25"

_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
    ' xmlns:xsd="http://www.w3.org/2001/XMLSchema"'
    ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
    "<soapenv:Body>{body}</soapenv:Body></soapenv:Envelope>"
)


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _esc(value) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


def parse_method(body) -> str:
    """Return the SOAP method name — the first element inside <soapenv:Body>."""
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else (body or "")
    m = re.search(r"<(?:[\w.-]+:)?Body[^>]*>\s*<(?:[\w.-]+:)?([A-Za-z][\w.]*)", text)
    return m.group(1) if m else ""


def envelope(inner: str) -> str:
    return _ENVELOPE.format(body=inner)


def _instance_uuid(token: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_DNS, f"vcenter-{token}"))


def service_content(token: str) -> str:
    """RetrieveServiceContent — the entry point; advertises the managers + 'VirtualCenter' apiType."""
    inner = f"""<RetrieveServiceContentResponse xmlns="{VIM_NS}"><returnval>
<rootFolder type="Folder">group-d1</rootFolder>
<propertyCollector type="PropertyCollector">propertyCollector</propertyCollector>
<viewManager type="ViewManager">ViewManager</viewManager>
<about>
<name>VMware vCenter Server</name>
<fullName>VMware vCenter Server 8.0.0 build-20519528</fullName>
<vendor>VMware, Inc.</vendor>
<version>8.0.0</version>
<build>20519528</build>
<localeVersion>INTL</localeVersion>
<localeBuild>000</localeBuild>
<osType>linux-x64</osType>
<productLineId>vpx</productLineId>
<apiType>VirtualCenter</apiType>
<apiVersion>8.0.0.0</apiVersion>
<instanceUuid>{_instance_uuid(token)}</instanceUuid>
<licenseProductName>VMware VirtualCenter Server</licenseProductName>
<licenseProductVersion>8.0</licenseProductVersion>
</about>
<setting type="OptionManager">VpxSettings</setting>
<userDirectory type="UserDirectory">UserDirectory</userDirectory>
<sessionManager type="SessionManager">SessionManager</sessionManager>
<authorizationManager type="AuthorizationManager">AuthorizationManager</authorizationManager>
<perfManager type="PerformanceManager">PerfMgr</perfManager>
<eventManager type="EventManager">EventManager</eventManager>
<taskManager type="TaskManager">TaskManager</taskManager>
<customFieldsManager type="CustomFieldsManager">CustomFieldsManager</customFieldsManager>
<rootSnapshot/>
</returnval></RetrieveServiceContentResponse>"""
    return envelope(inner)


def login_response(user: str) -> str:
    now = _now_iso()
    inner = f"""<LoginResponse xmlns="{VIM_NS}"><returnval>
<key>52{uuid.uuid4().hex}</key>
<userName>{_esc(user)}</userName>
<fullName>{_esc(user)}</fullName>
<loginTime>{now}</loginTime>
<lastActiveTime>{now}</lastActiveTime>
<locale>en</locale>
<messageLocale>en</messageLocale>
<extensionSession>false</extensionSession>
</returnval></LoginResponse>"""
    return envelope(inner)


def logout_response() -> str:
    return envelope(f'<LogoutResponse xmlns="{VIM_NS}"/>')


def current_time() -> str:
    return envelope(f'<CurrentTimeResponse xmlns="{VIM_NS}"><returnval>{_now_iso()}</returnval>'
                    "</CurrentTimeResponse>")


def _vms(dc) -> list[dict]:
    return (dc.content or {}).get("vms", []) or []


def _vm_propset(vm: dict, index: int) -> str:
    """A VirtualMachine object with the properties CloudGuard typically reads. Best-effort; the
    real PropertyCollector spec is captured in the Activity log so this can be tuned to match."""
    moid = f"vm-{index}"
    power = vm.get("power") or "poweredOn"
    ip = vm.get("ip") or ""
    name = vm.get("name") or moid
    guest_os = vm.get("guest_os") or "otherGuest"
    props = [
        ("name", "xsd:string", name),
        ("runtime.powerState", "VirtualMachinePowerState", power),
        ("guest.ipAddress", "xsd:string", ip),
        ("guest.hostName", "xsd:string", name),
        ("guest.guestState", "xsd:string", "running" if power == "poweredOn" else "notRunning"),
        ("config.guestFullName", "xsd:string", guest_os),
        ("config.uuid", "xsd:string", str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{name}-{ip}"))),
    ]
    propset = "".join(
        f'<propSet><name>{n}</name><val xsi:type="{t}">{_esc(v)}</val></propSet>'
        for n, t, v in props if v != ""
    )
    return f'<objects><obj type="VirtualMachine">{moid}</obj>{propset}</objects>'


def retrieve_properties(dc, *, ex: bool) -> str:
    """RetrieveProperties / RetrievePropertiesEx — enumerate the datacenter's VMs.

    NOTE: ignores the incoming PropertyFilterSpec for now and returns every VM with a common
    property set. Refine against the spec CloudGuard actually sends (visible in the Activity log).
    """
    objects = "".join(_vm_propset(vm, i + 1) for i, vm in enumerate(_vms(dc)))
    if ex:
        inner = (f'<RetrievePropertiesExResponse xmlns="{VIM_NS}"><returnval>{objects}'
                 "</returnval></RetrievePropertiesExResponse>")
    else:
        # RetrieveProperties returns the objects directly as the (repeated) returnval.
        inner = f'<RetrievePropertiesResponse xmlns="{VIM_NS}">{objects}</RetrievePropertiesResponse>'
    return envelope(inner)


def fault(message: str, detail: str = "") -> str:
    """A SOAP fault — used for methods we don't model yet (surfaced in the trace so we can add them)."""
    inner = ("<soapenv:Fault><faultcode>ServerFaultCode</faultcode>"
             f"<faultstring>{_esc(message)}</faultstring>"
             f"<detail>{detail}</detail></soapenv:Fault>")
    return envelope(inner)


# Methods that need an authenticated session (everything except the handshake/login/version calls).
_PUBLIC = {"RetrieveServiceContent", "Login", "CurrentTime", "Logout"}


def handle(dc, method: str, body) -> tuple[str, int, str]:
    """Dispatch a SOAP method to a response. Returns (xml, http_status, resolved_method)."""
    if method == "RetrieveServiceContent":
        return service_content(dc.token), 200, method
    if method == "Login":
        text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else (body or "")
        m = re.search(r"<userName>(.*?)</userName>", text, re.S)
        user = (m.group(1).strip() if m else "administrator@vsphere.local")
        return login_response(user), 200, method
    if method == "Logout":
        return logout_response(), 200, method
    if method == "CurrentTime":
        return current_time(), 200, method
    if method in ("RetrieveProperties", "RetrievePropertiesEx"):
        return retrieve_properties(dc, ex=method.endswith("Ex")), 200, method
    # Unknown / not-yet-modelled method: return a fault (logged) so we can see what to add next.
    return fault(f"Method '{method or 'unknown'}' is not modelled by the vCenter mock yet."), 500, method


VIM_SERVICE_VERSIONS = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<namespaces version="1.0">\n'
    " <namespace>\n"
    "  <name>urn:vim25</name>\n"
    "  <version>8.0.0.0</version>\n"
    "  <priorVersions>\n"
    "   <version>7.0.0.0</version>\n"
    "   <version>6.7.3</version>\n"
    "   <version>6.5</version>\n"
    "  </priorVersions>\n"
    " </namespace>\n"
    "</namespaces>\n"
)
