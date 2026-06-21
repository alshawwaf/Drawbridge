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

from . import dc_creds

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
    if not dc_creds.configured(cfg):
        return True
    return username == cfg.get("username") and bool(dc_creds.matches(cfg, password))


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
        ("config.uuid", "xsd:string", str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{moid}-{name}-{ip}"))),
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


# --- PropertyCollector update protocol (how CloudGuard actually enumerates VMs) ------------
# CloudGuard creates a container view + property filter, then calls WaitForUpdatesEx to receive
# the inventory as "enter" object updates. (It does NOT use RetrieveProperties.)
_COLLECTOR = "session[mock]propertyCollector"
_FILTER = "session[mock]propertyFilter"
_VIEW = "session[mock]containerView"


def _moref_response(method: str, motype: str, moid: str) -> str:
    return envelope(f'<{method}Response xmlns="{VIM_NS}">'
                    f'<returnval type="{motype}">{moid}</returnval></{method}Response>')


def void_response(method: str) -> str:
    return envelope(f'<{method}Response xmlns="{VIM_NS}"/>')


# Stable managed-object ids for the synthesized inventory containers (real-vCenter naming style).
# _ROOT must equal ServiceContent's rootFolder — CloudGuard's CreateFilter traverses from there.
_ROOT, _DC = "group-d1", "datacenter-2"
_VMF, _HOSTF, _NETF = "group-v22", "group-h4", "group-n23"
_CLUSTER, _RP = "domain-c7", "resgroup-8"
_HOSTS = ["host-13", "host-14"]
# Bump when the WaitForUpdates response SHAPE changes: it feeds the version token, so a bump forces
# the controller (which caches the last version per host) to re-sync with the new shape.
_SCHEMA_VERSION = "8"


def _moref(motype: str, moid: str) -> str:
    return f'<val xsi:type="ManagedObjectReference" type="{motype}">{moid}</val>'


def _moref_array(refs: list[tuple[str, str]]) -> str:
    items = "".join(f'<ManagedObjectReference type="{t}" xsi:type="ManagedObjectReference">{m}'
                    "</ManagedObjectReference>" for t, m in refs)
    return f'<val xsi:type="ArrayOfManagedObjectReference">{items}</val>'


def _str_val(text: str) -> str:
    return f'<val xsi:type="xsd:string">{_esc(text)}</val>'


def _string_array(values: list[str]) -> str:
    items = "".join(f'<string xsi:type="xsd:string">{_esc(v)}</string>' for v in values)
    return f'<val xsi:type="ArrayOfString">{items}</val>'


def _change(name: str, val_xml: str | None = None) -> str:
    # An UNSET requested property is still reported as a change-set with op=assign and NO <val> --
    # real vCenter does exactly this, and the scanner's fillProperties NPEs if a requested property's
    # change-set is missing entirely (this val-less `parent` on the root folder was the group-d1 NPE).
    return f"<changeSet><name>{name}</name><op>assign</op>{val_xml or ''}</changeSet>"


def _object_update(motype: str, moid: str, changes: list[str]) -> str:
    return (f'<objectSet><kind>enter</kind><obj type="{motype}">{moid}</obj>'
            f'{"".join(changes)}</objectSet>')


def inventory_object_updates(dc) -> list[str]:
    """The full vCenter inventory as PropertyCollector 'enter' object updates. The property set per
    type mirrors EXACTLY what CloudGuard's CreateFilter requests (all=false) — sending a property it
    didn't ask for makes the strict CXF client unable to reconcile the object with its filter, so it
    silently drops it. Containers are synthesized around the portal-defined VMs; parent/child refs
    make the tree navigable from the root folder (group-d1, == ServiceContent.rootFolder)."""
    vms = _vms(dc)
    vm_moids = [f"vm-{i + 1}" for i in range(len(vms))]
    objs = [
        # Folder -> name, parent, childEntity, childType (the full propSet; every requested property
        # is sent). The root folder's `parent` is a VAL-LESS change-set (unset) -- captured from a
        # real vCenter; omitting it was the group-d1 NPE. childType values are BARE ("Folder", not
        # "vim.Folder" -- the MOB only displays the vim.* form; the wire value is bare).
        _object_update("Folder", _ROOT, [
            _change("name", _str_val("Datacenters")),
            _change("parent"),
            _change("childEntity", _moref_array([("Datacenter", _DC)])),
            _change("childType", _string_array(["Folder", "Datacenter"])),
        ]),
        # Datacenter -> name, parent, hostFolder, vmFolder, networkFolder
        _object_update("Datacenter", _DC, [
            _change("name", _str_val("Datacenter")),
            _change("parent", _moref("Folder", _ROOT)),
            _change("hostFolder", _moref("Folder", _HOSTF)),
            _change("vmFolder", _moref("Folder", _VMF)),
            _change("networkFolder", _moref("Folder", _NETF)),
        ]),
        _object_update("Folder", _VMF, [
            _change("name", _str_val("vm")),
            _change("parent", _moref("Datacenter", _DC)),
            _change("childEntity", _moref_array([("VirtualMachine", m) for m in vm_moids])),
            _change("childType", _string_array(["Folder", "VirtualMachine", "VirtualApp"])),
        ]),
        _object_update("Folder", _HOSTF, [
            _change("name", _str_val("host")),
            _change("parent", _moref("Datacenter", _DC)),
            _change("childEntity", _moref_array([("ClusterComputeResource", _CLUSTER)])),
            _change("childType", _string_array(["Folder", "ComputeResource"])),
        ]),
        # ClusterComputeResource -> name, parent, resourcePool (hosts/VMs link back via their parent)
        _object_update("ClusterComputeResource", _CLUSTER, [
            _change("name", _str_val("Cluster")),
            _change("parent", _moref("Folder", _HOSTF)),
            _change("resourcePool", _moref("ResourcePool", _RP)),
        ]),
        # ResourcePool -> name, parent
        _object_update("ResourcePool", _RP, [
            _change("name", _str_val("Resources")),
            _change("parent", _moref("ClusterComputeResource", _CLUSTER)),
        ]),
    ]
    # HostSystem -> name, parent
    for i, host in enumerate(_HOSTS):
        objs.append(_object_update("HostSystem", host, [
            _change("name", _str_val(f"esxi-0{i + 1}.lab.local")),
            _change("parent", _moref("ClusterComputeResource", _CLUSTER)),
        ]))
    # VirtualMachine -> the FULL propSet CloudGuard requests; properties we don't model are still
    # sent as val-less change-sets (matching real vCenter) so fillProperties never hits a null.
    for i, vm in enumerate(vms):
        moid = vm_moids[i]
        name = vm.get("name") or moid
        ip = vm.get("ip") or ""
        objs.append(_object_update("VirtualMachine", moid, [
            _change("name", _str_val(name)),
            _change("parent", _moref("Folder", _VMF)),
            _change("parentVApp"),                                       # not in a vApp -> unset
            _change("config.annotation", _str_val(vm.get("notes") or "")),
            _change("guest.net"),                                        # per-NIC detail not modeled
            _change("guest.ipAddress", _str_val(ip) if ip else None),
            _change("resourcePool", _moref("ResourcePool", _RP)),
            _change("config.managedBy"),                                 # unset
            _change("config.instanceUuid", _str_val(str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{dc.token}-{moid}-iu")))),
            _change("config.tools"),                                     # ToolsConfigInfo not modeled
        ]))
    # Emit CHILDREN before PARENTS. CloudGuard's scanner resolves downward refs (childEntity,
    # vmFolder, hostFolder, host, resourcePool) eagerly as it fills each object, so a parent that
    # arrives before its children NPEs (it was the root folder group-d1 -> childEntity -> a
    # not-yet-seen Datacenter). Reversed, every downward ref points at an already-received object;
    # `parent` refs point the other way but aren't traversal paths, so they're resolved lazily.
    return list(reversed(objs))


def _inventory_version(dc) -> str:
    """A token for the CURRENT inventory state. We return it as the WaitForUpdates version; the
    client echoes it back, and only when it matches do we report no changes. Crucially, ANY other
    version — an empty first call, OR a version the controller cached from a prior sync — triggers a
    full re-delivery. (CloudGuard caches the last version per host and reuses it, so a fixed '1'
    would freeze the inventory forever; deriving the token from the data avoids that and also makes
    edits to the datacenter re-sync automatically.)"""
    vms = _vms(dc)
    epoch = (dc.content or {}).get("_vc_epoch", "")  # bumped on CreateFilter -> a reconnect re-syncs
    seed = f"{_SCHEMA_VERSION}|{epoch}|" + "|".join(
        f"{v.get('name')}={v.get('ip')}:{v.get('power')}:{','.join(v.get('tags') or [])}" for v in vms)
    return "dcsim-" + uuid.uuid5(uuid.NAMESPACE_DNS, seed).hex[:12]


def invalid_collector_version_fault() -> str:
    """The fault real vCenter raises when a client polls with a version the current collector never
    issued (e.g. a version cached from a destroyed filter/session after a reconnect). It is the
    signal that makes the controller RESET — re-poll with an empty version for a clean initial sync.
    Without it, a controller that persists+reuses its version starves a freshly-created filter."""
    return fault("The specified version was not valid for the current PropertyCollector.",
                 '<InvalidCollectorVersion xmlns="urn:vim25" xsi:type="InvalidCollectorVersion">'
                 "</InvalidCollectorVersion>")


def wait_for_updates(dc, body, *, ex: bool) -> tuple[str, int]:
    """WaitForUpdates[Ex] with real vCenter version semantics, returning (xml, http_status):
      - empty version (initial sync, or after a reset) -> deliver the full inventory as 'enter';
      - the current token (client is up to date)       -> no further changes;
      - any other (stale/cached) version               -> InvalidCollectorVersion fault, which makes
        the controller reset to an empty version. This last case is essential: CloudGuard persists
        its version and reuses it on a fresh filter, so we must reject it to trigger a clean sync."""
    text = body.decode("utf-8", "replace") if isinstance(body, (bytes, bytearray)) else (body or "")
    m = re.search(r"<version>(.*?)</version>", text, re.S)
    version = m.group(1).strip() if m else ""
    current = _inventory_version(dc)
    resp = "WaitForUpdatesExResponse" if ex else "WaitForUpdatesResponse"
    if version and version != current:          # stale version from a prior collector -> force reset
        return invalid_collector_version_fault(), 500
    if version == current:                       # already holds the current inventory -> no changes
        return (envelope(f'<{resp} xmlns="{VIM_NS}"><returnval><version>{current}</version>'
                         f'<truncated>false</truncated></returnval></{resp}>'), 200)
    objects = "".join(inventory_object_updates(dc))   # empty version -> full initial state
    filter_set = f'<filterSet><filter type="PropertyFilter">{_FILTER}</filter>{objects}</filterSet>'
    return (envelope(f'<{resp} xmlns="{VIM_NS}"><returnval><version>{current}</version>{filter_set}'
                     f'<truncated>false</truncated></returnval></{resp}>'), 200)


def tag_catalog(dc) -> dict:
    """vCenter tags derived from the VMs' `tags`, in the vSphere tagging-service shape. One category
    groups every distinct tag; each tag is associated with the VMs that carry it. VM moids match the
    WaitForUpdates enumeration (vm-1, vm-2, ...) so CloudGuard links tags to the imported VMs."""
    vms = _vms(dc)
    names: list[str] = []
    for vm in vms:
        for tag in (vm.get("tags") or []):
            if tag and tag not in names:
                names.append(tag)
    cat_id = ("urn:vmomi:InventoryServiceCategory:"
              + str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{dc.token}-category")) + ":GLOBAL")
    category = {"id": cat_id, "name": "CloudGuard", "description": "Tags imported by CloudGuard",
                "cardinality": "MULTIPLE", "associable_types": ["VirtualMachine"], "used_by": []}
    tags, assoc = [], {}
    for name in names:
        tid = ("urn:vmomi:InventoryServiceTag:"
               + str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{dc.token}-tag-{name}")) + ":GLOBAL")
        tags.append({"id": tid, "name": name, "description": "", "category_id": cat_id, "used_by": []})
        assoc[tid] = [f"vm-{i + 1}" for i, vm in enumerate(vms) if name in (vm.get("tags") or [])]
    return {"category": category, "tags": tags, "assoc": assoc}


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
    # PropertyCollector update protocol — how CloudGuard actually enumerates VMs.
    if method == "CreatePropertyCollector":
        return _moref_response(method, "PropertyCollector", _COLLECTOR), 200, method
    if method == "CreateContainerView":
        return _moref_response(method, "ContainerView", _VIEW), 200, method
    if method == "CreateFilter":
        return _moref_response(method, "PropertyFilter", _FILTER), 200, method
    if method in ("WaitForUpdates", "WaitForUpdatesEx"):
        xml, status = wait_for_updates(dc, body, ex=method.endswith("Ex"))
        return xml, status, method
    if method in ("DestroyPropertyFilter", "CancelWaitForUpdates",
                  "DestroyPropertyCollector", "DestroyView"):
        return void_response(method), 200, method
    # Unknown / not-yet-modelled method: return a fault (logged) so we can see what to add next.
    return fault(f"Method '{method or 'unknown'}' is not modelled by the vCenter mock yet."), 500, method


# Matched byte-for-byte to a real vCenter 8.0.3 /sdk/vimServiceVersions.xml (full version list).
VIM_SERVICE_VERSIONS = (
    '<?xml version="1.0" encoding="UTF-8" ?><namespaces version="1.0"><namespace>'
    '<name>urn:vim25</name><version>8.0.3.0</version><priorVersions>'
    '<version>8.0.2.0</version><version>8.0.1.0</version><version>8.0.0.2</version>'
    '<version>8.0.0.1</version><version>8.0.0.0</version><version>7.0.3.2</version>'
    '<version>7.0.3.1</version><version>7.0.3.0</version><version>7.0.2.1</version>'
    '<version>7.0.2.0</version><version>7.0.1.1</version><version>7.0.1.0</version>'
    '<version>7.0.0.2</version><version>7.0.0.0</version><version>6.9.1</version>'
    '<version>6.8.7</version><version>6.7.3</version><version>6.7.2</version>'
    '<version>6.7.1</version><version>6.7</version><version>6.5</version>'
    '<version>6.0</version><version>5.5</version><version>5.1</version>'
    '<version>5.0</version><version>4.1</version><version>4.0</version>'
    "</priorVersions></namespace></namespaces>"
)
