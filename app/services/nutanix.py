"""Build Nutanix Prism **REST** responses from a Datacenter's simulated inventory.

CloudGuard Controller R82.10's Nutanix scanner imports **VMs** (with their NIC IPs) and **Categories**
(Prism's key/value tags), and associates VMs with the categories applied to them. It probes **Prism
v4** first and falls back to **v3** (both modeled here so either path works). Auth is HTTP **Basic**
(``Authorization: Basic <base64(user:pass)>``). Confirmed from the decompiled scanner (cms.jar
``com/checkpoint/datacenter/scanner/nutanix``):

- ``NutanixApi`` endpoints — v3: ``POST /api/nutanix/v3/vms/list``, ``POST …/categories/list``,
  ``POST …/categories/{name}/list``, ``POST …/category/query``, ``GET …/users/me``; v4:
  ``GET /api/vmm/v4.1/ahv/config/vms`` (``?$limit=1`` = test connection),
  ``GET /api/prism/v4.1/config/categories``.
- ``NutanixScanner`` builds ``updateRoot`` → ``updateVMsV3/V4`` + ``updateCategoriesV3/V4`` +
  ``createCategoryHierarchy`` (Key repository → Value folders → VMs via ``buildCategoryAssociations`` /
  ``addVmToCategory``). So a Category Key is a folder, each Value a sub-folder, and the VMs carrying
  ``key=value`` nest under it (a category resolves to those VMs' IPs).
- Model fields — v3: VM ``{metadata{uuid,categories}, status{name,description,resources{nic_list[]
  {ip_endpoint_list[]{ip}}}}}``, VMsList ``{api_version,metadata,entities[]}``, Category ``{name}``;
  v4: VMv4 ``{extId,name,description,nics[]{networkInfo{ipv4Info{learnedIpAddresses[]{value}}}},
  categories[]{extId}}``, CategoryV4 ``{extId,key,value}``, list ``{data[],metadata{
  totalAvailableResults,hasMorePages}}``.
"""
import base64
import uuid

from . import dc_creds

_UID_NS = uuid.UUID("00000000-0000-0000-0000-0000000c0ffe")


def _uid(*parts: str) -> str:
    return str(uuid.uuid5(_UID_NS, "/".join(parts)))


def _vms(dc) -> list[dict]:
    return (dc.content or {}).get("vms", []) or []


def _ips(vm: dict) -> list[str]:
    return vm.get("ips") or ([vm["ip"]] if vm.get("ip") else [])


def _vm_categories(vm: dict) -> dict:
    return vm.get("categories") or {}


def categories(dc) -> dict:
    """Category key → sorted list of its values, derived from the VMs' ``categories`` maps (plus any
    explicit ``content['categories']`` of the same shape)."""
    out: dict[str, list[str]] = {}
    for k, vals in ((dc.content or {}).get("categories") or {}).items():
        out.setdefault(k, [])
        out[k].extend(vals if isinstance(vals, list) else [vals])
    for vm in _vms(dc):
        for k, v in _vm_categories(vm).items():
            out.setdefault(k, [])
            if v not in out[k]:
                out[k].append(v)
    return {k: sorted(set(v)) for k, v in out.items()}


# --- Prism v3 (POST list APIs) --------------------------------------------------------------

def _v3_envelope(kind: str, entities: list[dict]) -> dict:
    return {"api_version": "3.1", "metadata": {"kind": kind, "total_matches": len(entities),
                                               "length": len(entities), "offset": 0}, "entities": entities}


def users_me() -> dict:
    """``GET /api/nutanix/v3/users/me`` — the whoami CloudGuard uses to validate the connection."""
    return {"metadata": {"kind": "user"}, "spec": {}, "status": {"name": "admin",
            "resources": {"user_type": "LOCAL", "display_name": "admin"}}}


def vms_list_v3(dc) -> dict:
    """``POST /api/nutanix/v3/vms/list`` — VMs with NIC IPs and their applied categories."""
    ents = []
    for vm in _vms(dc):
        nic_list = [{"ip_endpoint_list": [{"ip": ip, "type": "ASSIGNED"} for ip in _ips(vm)],
                     "mac_address": "50:6b:8d:00:00:01"}]
        cats = _vm_categories(vm)
        ents.append({
            "metadata": {"kind": "vm", "uuid": _uid("vm", vm["name"]), "categories": cats,
                         "categories_mapping": {k: [v] for k, v in cats.items()}},
            "status": {"name": vm["name"], "description": vm.get("description", ""), "state": "COMPLETE",
                       "resources": {"power_state": "ON", "nic_list": nic_list}},
            "spec": {"name": vm["name"], "resources": {"nic_list": nic_list}},
        })
    return _v3_envelope("vm", ents)


def categories_list_v3(dc) -> dict:
    """``POST /api/nutanix/v3/categories/list`` — the category KEYS."""
    ents = [{"name": k, "description": f"{k} category", "system_defined": False}
            for k in categories(dc)]
    return _v3_envelope("category", ents)


def category_values_v3(dc, name: str) -> dict:
    """``POST /api/nutanix/v3/categories/{name}/list`` — the VALUES of one category key."""
    ents = [{"name": name, "value": v, "description": "", "system_defined": False}
            for v in categories(dc).get(name, [])]
    return _v3_envelope("category", ents)


def category_query_v3(dc, body: dict | None = None) -> dict:
    """``POST /api/nutanix/v3/category/query`` — which VMs are tagged with the requested category
    value(s). CloudGuard uses this to associate VMs with categories. ``body.category_filter.params``
    is ``{key: [values]}``; with no filter we return every VM."""
    params = ((body or {}).get("category_filter") or {}).get("params") or {}
    refs = []
    for vm in _vms(dc):
        vc = _vm_categories(vm)
        if not params or any(vc.get(k) in vals for k, vals in params.items()):
            refs.append({"kind": "vm", "uuid": _uid("vm", vm["name"]), "name": vm["name"]})
    return {"api_version": "3.1", "metadata": {"kind": "category", "total_matches": len(refs)},
            "results": [{"kind": "vm", "total_entity_count": len(refs), "kind_reference_list": refs}]}


# --- Prism v4 (GET APIs) --------------------------------------------------------------------

def _v4_envelope(data: list[dict]) -> dict:
    return {"data": data, "metadata": {"totalAvailableResults": len(data), "hasMorePages": False,
                                       "flags": [], "links": []}}


def vms_list_v4(dc) -> dict:
    """``GET /api/vmm/v4.1/ahv/config/vms`` — v4 VMs (IPs in ``nics[].networkInfo.ipv4Info
    .learnedIpAddresses[]``, categories by extId reference)."""
    data = []
    for vm in _vms(dc):
        ips = _ips(vm)
        nic = {"extId": _uid("nic", vm["name"]),
               "networkInfo": {"ipv4Config": ({"ipAddress": {"value": ips[0]}} if ips else {}),
                               "ipv4Info": {"learnedIpAddresses": [{"value": ip} for ip in ips]}}}
        data.append({"extId": _uid("vm", vm["name"]), "name": vm["name"],
                     "description": vm.get("description", ""), "powerState": "ON", "nics": [nic],
                     "categories": [{"extId": _uid("cat", k, v)}
                                    for k, v in _vm_categories(vm).items()]})
    return _v4_envelope(data)


def categories_list_v4(dc) -> dict:
    """``GET /api/prism/v4.1/config/categories`` — v4 categories as flat key/value pairs."""
    data = [{"extId": _uid("cat", k, v), "key": k, "value": v, "description": "", "type": "USER"}
            for k, vals in categories(dc).items() for v in vals]
    return _v4_envelope(data)


# --- auth (HTTP Basic) ----------------------------------------------------------------------

def _basic(authorization: str):
    s = (authorization or "").strip()
    if s[:6].lower() != "basic ":
        return None, None
    try:
        user, _, pwd = base64.b64decode(s[6:].strip()).decode("utf-8", "replace").partition(":")
        return user, pwd
    except Exception:
        return None, None


def auth_ok(dc, authorization: str) -> bool:
    """Validate Basic credentials against the datacenter's configured ones; permissive if none set."""
    cfg = (dc.content or {}).get("auth") or {}
    if not dc_creds.configured(cfg):
        return True                                   # open lab — accept any (or no) credentials
    user, pwd = _basic(authorization)
    if user is None:
        return False
    return user == cfg.get("username") and bool(dc_creds.matches(cfg, pwd))


def authorized(dc, authorization: str = "") -> bool:
    return auth_ok(dc, authorization)


def unauthorized() -> dict:
    """Prism 401 error envelope."""
    return {"api_version": "3.1", "code": 401, "state": "ERROR",
            "message_list": [{"message": "Authentication required.", "reason": "AUTHENTICATION_REQUIRED"}]}
