"""Build Cisco ACI / APIC **REST** responses from a Datacenter's simulated inventory.

CloudGuard Controller R82.10 (Cisco ACI scanner) imports **Tenant → Application Profile → EPG**,
**ESG**, L2 Out / L2 External EPG, and the **endpoints** (with IPs) behind each group. It logs in at
``POST /api/aaaLogin.json`` (returns a token used as the ``APIC-cookie``), then runs APIC **class
queries** ``GET /api/node/class/<class>.json``. Every APIC response is the
``{"totalCount": "N", "imdata": [ { "<class>": {"attributes": {...}, "children": [...]} } ]}`` shape.

First cut — built to the R82.10 admin guide + the public APIC API. The exact classes CloudGuard
queries are confirmed from the portal Activity log and the responses tuned to match.
"""
import uuid

from ..security import verify_password

_NS = uuid.UUID("00000000-0000-0000-0000-0000000ac1c0")


def _tenant(dc) -> str:
    return (dc.content or {}).get("tenant") or "DCSIM"


def _ap(dc) -> str:
    return (dc.content or {}).get("app_profile") or "DCSIM-AP"


def _epgs(dc) -> list[dict]:
    return (dc.content or {}).get("epgs", []) or []


def _esgs(dc) -> list[dict]:
    return (dc.content or {}).get("esgs", []) or []


def _mac(ip: str) -> str:
    """Deterministic MAC for an endpoint IP (VMware OUI + the IP's last three octets)."""
    parts = (ip.split(".") + ["0", "0", "0", "0"])[:4]
    try:
        o = [int(p) & 0xFF for p in parts[1:4]]
    except ValueError:
        o = [0, 0, 0]
    return "00:50:56:%02X:%02X:%02X" % (o[0], o[1], o[2])


def imdata(objs: list) -> dict:
    """The APIC response envelope (also the safe empty-collection response)."""
    return {"totalCount": str(len(objs)), "imdata": objs}


def _mo(cls: str, attrs: dict, children: list | None = None) -> dict:
    mo = {cls: {"attributes": attrs}}
    if children is not None:
        mo[cls]["children"] = children
    return mo


# --- class-query object builders ------------------------------------------------------------

def _tenant_dn(dc) -> str:
    return f"uni/tn-{_tenant(dc)}"


def _ap_dn(dc) -> str:
    return f"{_tenant_dn(dc)}/ap-{_ap(dc)}"


def tenants(dc) -> list[dict]:
    return [_mo("fvTenant", {"dn": _tenant_dn(dc), "name": _tenant(dc),
                             "descr": "DC Integration Simulator tenant"})]


def app_profiles(dc) -> list[dict]:
    return [_mo("fvAp", {"dn": _ap_dn(dc), "name": _ap(dc)})]


def epgs(dc) -> list[dict]:
    return [_mo("fvAEPg", {"dn": f"{_ap_dn(dc)}/epg-{g['name']}", "name": g["name"],
                           "pcEnfPref": "unenforced"}) for g in _epgs(dc)]


def endpoints(dc) -> list[dict]:
    """fvCEp — one client endpoint per EPG member IP, dn under its EPG so CloudGuard maps it back."""
    res = []
    for g in _epgs(dc):
        for ip in g.get("ips", []) or []:
            mac = _mac(ip)
            res.append(_mo("fvCEp", {"dn": f"{_ap_dn(dc)}/epg-{g['name']}/cep-{mac}",
                                     "name": mac, "mac": mac, "ip": ip, "encap": "vlan-100"}))
    return res


def esgs(dc) -> list[dict]:
    """fvESg — each ESG carries IP-based endpoint selectors (fvEPSelector) for its member IPs, so the
    group resolves to addresses rather than being an empty object."""
    res = []
    for g in _esgs(dc):
        sel = [_mo("fvEPSelector", {"name": f"ip-{ip}", "matchExpression": f"ip=='{ip}'"})
               for ip in g.get("ips", []) or []]
        res.append(_mo("fvESg", {"dn": f"{_ap_dn(dc)}/esg-{g['name']}", "name": g["name"]}, sel))
    return res


def ep_selectors(dc) -> list[dict]:
    """Flattened fvEPSelector list (in case CloudGuard queries the class directly)."""
    out = []
    for g in _esgs(dc):
        for ip in g.get("ips", []) or []:
            out.append(_mo("fvEPSelector", {"dn": f"{_ap_dn(dc)}/esg-{g['name']}/epselector-ip-{ip}",
                                            "matchExpression": f"ip=='{ip}'"}))
    return out


# className → builder. Anything else returns an empty imdata (safe for enumeration).
_CLASSES = {
    "fvTenant": tenants, "fvAp": app_profiles, "fvAEPg": epgs, "fvCEp": endpoints,
    "fvESg": esgs, "fvEPSelector": ep_selectors,
    "l2extOut": lambda dc: [], "l2extInstP": lambda dc: [],
}


def class_query(dc, class_name: str) -> dict:
    """Answer ``GET /api/node/class/<class_name>.json``. Strips a trailing ``.json``/``.xml``."""
    cls = class_name.rsplit(".", 1)[0] if class_name.endswith((".json", ".xml")) else class_name
    return imdata(_CLASSES.get(cls, lambda dc: [])(dc))


# --- auth (APIC login → APIC-cookie) --------------------------------------------------------

def auth_ok(dc, username: str, password: str) -> bool:
    cfg = (dc.content or {}).get("auth") or {}
    if not cfg.get("password_hash"):
        return True
    return username == cfg.get("username") and verify_password(password, cfg["password_hash"])


def authorized(dc, *, apic_cookie: str = "") -> bool:
    """Open when no creds configured; otherwise requires the APIC-cookie we issued at login."""
    cfg = (dc.content or {}).get("auth") or {}
    if not cfg.get("password_hash"):
        return True
    return bool(apic_cookie)


def login_response(username: str) -> dict:
    """``POST /api/aaaLogin.json`` success — the token CloudGuard then sends as the APIC-cookie."""
    token = uuid.uuid4().hex
    return token, imdata([_mo("aaaLogin", {
        "token": token, "refreshTimeoutSeconds": "600", "maximumLifetimeSeconds": "86400",
        "userName": username or "admin", "restTimeoutSeconds": "90"})])


def forbidden() -> dict:
    """APIC error envelope for a rejected request / bad credentials."""
    return imdata([_mo("error", {"code": "401", "text": "Authentication failed."})])
