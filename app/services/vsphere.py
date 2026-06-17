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

from ..security import verify_password

VIM_NS = "urn:vim25"

_ENVELOPE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<soapenv:Envelope xmlns:soapenc="http://schemas.xmlsoap.org/soap/encoding/"'
    ' xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"'
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


def service_content(token: str = "") -> str:
    """RetrieveServiceContent — matched byte-for-byte to a real vCenter 8.0.3 ServiceContent
    (exact manager set, order, and AboutInfo). The vSphere SDK deserializer is element- and
    order-sensitive, so this mirrors a captured real response rather than an approximation."""
    inner = (
        f'<RetrieveServiceContentResponse xmlns="{VIM_NS}"><returnval>'
        '<rootFolder type="Folder">group-d1</rootFolder>'
        '<propertyCollector type="PropertyCollector">propertyCollector</propertyCollector>'
        '<viewManager type="ViewManager">ViewManager</viewManager>'
        '<about><name>VMware vCenter Server</name>'
        '<fullName>VMware vCenter Server 8.0.3 build-24022515</fullName>'
        '<vendor>VMware, Inc.</vendor><version>8.0.3</version><build>24022515</build>'
        '<localeVersion>INTL</localeVersion><localeBuild>000</localeBuild>'
        '<osType>linux-x64</osType><productLineId>vpx</productLineId>'
        '<apiType>VirtualCenter</apiType><apiVersion>8.0.3.0</apiVersion></about>'
        '<setting type="OptionManager">VpxSettings</setting>'
        '<userDirectory type="UserDirectory">UserDirectory</userDirectory>'
        '<sessionManager type="SessionManager">SessionManager</sessionManager>'
        '<authorizationManager type="AuthorizationManager">AuthorizationManager</authorizationManager>'
        '<perfManager type="PerformanceManager">PerfMgr</perfManager>'
        '<scheduledTaskManager type="ScheduledTaskManager">ScheduledTaskManager</scheduledTaskManager>'
        '<alarmManager type="AlarmManager">AlarmManager</alarmManager>'
        '<eventManager type="EventManager">EventManager</eventManager>'
        '<taskManager type="TaskManager">TaskManager</taskManager>'
        '<extensionManager type="ExtensionManager">ExtensionManager</extensionManager>'
        '<customizationSpecManager type="CustomizationSpecManager">CustomizationSpecManager</customizationSpecManager>'
        '<customFieldsManager type="CustomFieldsManager">CustomFieldsManager</customFieldsManager>'
        '<diagnosticManager type="DiagnosticManager">DiagMgr</diagnosticManager>'
        '<licenseManager type="LicenseManager">LicenseManager</licenseManager>'
        '<searchIndex type="SearchIndex">SearchIndex</searchIndex>'
        '<fileManager type="FileManager">FileManager</fileManager>'
        '<virtualDiskManager type="VirtualDiskManager">virtualDiskManager</virtualDiskManager>'
        '</returnval></RetrieveServiceContentResponse>'
    )
    return envelope(inner)


def session_key() -> str:
    return f"52{uuid.uuid4().hex}"


def login_response(user: str, key: str) -> str:
    # UserSession has NO optional fields — every element below is required (vim25 schema), so a
    # strict client rejects the response if any is missing. Order matches the WSDL sequence.
    now = _now_iso()
    inner = f"""<LoginResponse xmlns="{VIM_NS}"><returnval>
<key>{_esc(key)}</key>
<userName>{_esc(user)}</userName>
<fullName>{_esc(user)}</fullName>
<loginTime>{now}</loginTime>
<lastActiveTime>{now}</lastActiveTime>
<locale>en</locale>
<messageLocale>en</messageLocale>
<extensionSession>false</extensionSession>
<ipAddress>127.0.0.1</ipAddress>
<userAgent>CloudGuard Controller</userAgent>
<callCount>0</callCount>
</returnval></LoginResponse>"""
    return envelope(inner)


def _unescape(s: str) -> str:
    return (s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"')
            .replace("&apos;", "'").replace("&amp;", "&"))


def auth_ok(dc, username: str, password: str) -> bool:
    """Validate the SOAP Login credentials against the datacenter's configured ones; permissive
    if none are configured."""
    cfg = (dc.content or {}).get("auth") or {}
    if not cfg.get("password_hash"):
        return True
    return username == cfg.get("username") and verify_password(password, cfg["password_hash"])


def login_fault() -> str:
    """vSphere InvalidLogin fault — what real vCenter returns for bad credentials."""
    inner = ('<soapenv:Fault><faultcode>ServerFaultCode</faultcode>'
             '<faultstring>Cannot complete login due to an incorrect user name or password.'
             '</faultstring><detail>'
             f'<InvalidLoginFault xmlns="{VIM_NS}" xsi:type="InvalidLogin"/></detail>'
             '</soapenv:Fault>')
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
        pm = re.search(r"<password>(.*?)</password>", text, re.S)
        password = _unescape(pm.group(1)) if pm else ""
        if not auth_ok(dc, user, password):   # wrong creds -> real vCenter InvalidLogin fault
            return login_fault(), 500, method
        return login_response(user, session_key()), 200, method
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
