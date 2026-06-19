"""Build Cisco ACI / APIC **REST** responses from a Datacenter's simulated inventory.

CloudGuard Controller R82.10 (Cisco ACI scanner) imports **Tenant → Application Profile → EPG**,
**ESG**, L2 Out / L2 External EPG, and the **endpoints** (with IPs) behind each group. It logs in at
``POST /api/aaaLogin.xml`` (token returned + set as the ``APIC-cookie``), then runs APIC **class
queries** ``GET /api/node/class/<class>.xml``.

**CloudGuard's APIC client is XML-only** (it JAXB-unmarshals every response — JSON makes it fail with
"Content is not allowed in prolog"), so the default render here is **XML**:
``<imdata totalCount="N"><fvTenant dn="…" name="…"/>…</imdata>``. We also render JSON for ``.json``
(real APIC is dual-format; handy for shell/`curl` testing).
"""
import uuid
import xml.sax.saxutils as _su

from . import dc_creds

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


def _mo(cls: str, attrs: dict, children: list | None = None) -> dict:
    mo = {cls: {"attributes": attrs}}
    if children is not None:
        mo[cls]["children"] = children
    return mo


# Every real APIC managed object carries these standard attributes. ``status`` is the critical one:
# CloudGuard's AciScannerPropertiesConverter does ``mo.getModificationStatus().ordinal()`` for the
# tenant/AP/EPG/ESG/endpoint (cms.jar). ApicMo binds ``status`` as an @XmlEnum
# {NONE(""), CREATED("created"), MODIFIED("modified"), DELETED("deleted")}; omit it and it unmarshals
# to null → NullPointerException, which fails the whole scan ("Data Center is still initializing").
# ``created`` is the enum's create path, so the object is imported. nameAlias/descr default empty so
# their getters never return null either. (Attributes a given class doesn't define are ignored —
# ApicMo uses @XmlAccessorType(NONE), so unknown XML attributes are dropped on unmarshal.)
_MO_DEFAULTS = {"status": "created", "nameAlias": "", "descr": ""}


def _attrs(d: dict) -> dict:
    out = dict(d)
    for k, v in _MO_DEFAULTS.items():
        out.setdefault(k, v)
    return out


# --- renderers: APIC is dual-format; CloudGuard uses XML --------------------------------------

def imdata(objs: list) -> dict:
    """JSON envelope (also the safe empty-collection response for the .json path / tests)."""
    return {"totalCount": str(len(objs)), "imdata": objs}


def _mo_xml(mo: dict) -> str:
    (cls, body), = mo.items()
    attrs = "".join(f" {k}={_su.quoteattr(str(v))}" for k, v in (body.get("attributes") or {}).items())
    children = body.get("children") or []
    if children:
        return f"<{cls}{attrs}>" + "".join(_mo_xml(c) for c in children) + f"</{cls}>"
    return f"<{cls}{attrs}/>"


def to_xml(objs: list) -> str:
    """APIC XML envelope — the format CloudGuard's APIC client unmarshals."""
    inner = "".join(_mo_xml(m) for m in objs)
    return f'<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="{len(objs)}">{inner}</imdata>'


# --- class-query object builders ------------------------------------------------------------

def _tenant_dn(dc) -> str:
    return f"uni/tn-{_tenant(dc)}"


def _ap_dn(dc) -> str:
    return f"{_tenant_dn(dc)}/ap-{_ap(dc)}"


def tenants(dc) -> list[dict]:
    return [_mo("fvTenant", _attrs({"dn": _tenant_dn(dc), "name": _tenant(dc),
                                    "descr": "DC Integration Simulator tenant"}))]


def app_profiles(dc) -> list[dict]:
    return [_mo("fvAp", _attrs({"dn": _ap_dn(dc), "name": _ap(dc)}))]


def epgs(dc) -> list[dict]:
    return [_mo("fvAEPg", _attrs({"dn": f"{_ap_dn(dc)}/epg-{g['name']}", "name": g["name"],
                                  "pcEnfPref": "unenforced"})) for g in _epgs(dc)]


def endpoints(dc) -> list[dict]:
    """fvCEp — one client endpoint per EPG member IP, dn under its EPG so CloudGuard maps it back."""
    res = []
    for g in _epgs(dc):
        for ip in g.get("ips", []) or []:
            mac = _mac(ip)
            res.append(_mo("fvCEp", _attrs({"dn": f"{_ap_dn(dc)}/epg-{g['name']}/cep-{mac}",
                                            "name": mac, "mac": mac, "ip": ip, "encap": "vlan-100"})))
    return res


def esgs(dc) -> list[dict]:
    """fvESg — each ESG carries IP-based endpoint selectors (fvEPSelector) for its member IPs, so the
    group resolves to addresses rather than being an empty object."""
    res = []
    for g in _esgs(dc):
        sel = [_mo("fvEPSelector", _attrs({"name": f"ip-{ip}", "matchExpression": f"ip=='{ip}'"}))
               for ip in g.get("ips", []) or []]
        res.append(_mo("fvESg", _attrs({"dn": f"{_ap_dn(dc)}/esg-{g['name']}", "name": g["name"]}), sel))
    return res


def ep_selectors(dc) -> list[dict]:
    """Flattened fvEPSelector list (in case CloudGuard queries the class directly)."""
    out = []
    for g in _esgs(dc):
        for ip in g.get("ips", []) or []:
            out.append(_mo("fvEPSelector", _attrs({"dn": f"{_ap_dn(dc)}/esg-{g['name']}/epselector-ip-{ip}",
                                                   "matchExpression": f"ip=='{ip}'"})))
    return out


# className → builder. Anything else returns an empty imdata (safe for enumeration).
_CLASSES = {
    "fvTenant": tenants, "fvAp": app_profiles, "fvAEPg": epgs, "fvCEp": endpoints,
    "fvESg": esgs, "fvEPSelector": ep_selectors,
    "l2extOut": lambda dc: [], "l2extInstP": lambda dc: [],
}


def class_objects(dc, class_name: str) -> list[dict]:
    """The managed objects for ``GET /api/node/class/<class_name>`` (strips a trailing format ext)."""
    cls = class_name.rsplit(".", 1)[0] if class_name.endswith((".json", ".xml")) else class_name
    return _CLASSES.get(cls, lambda dc: [])(dc)


def class_query(dc, class_name: str) -> dict:
    """JSON form of a class query (used by the .json path and the tests)."""
    return imdata(class_objects(dc, class_name))


def _dn(mo: dict) -> str:
    return next(iter(mo.values()))["attributes"].get("dn", "")


def _flat_mos(dc) -> list[dict]:
    """Every managed object as a flat wire-MO (ESGs without nested children here — ``_nest`` re-parents
    by DN; the class query still nests an ESG's selectors via ``esgs()``)."""
    flat = tenants(dc) + app_profiles(dc) + epgs(dc) + endpoints(dc)
    flat += [_mo("fvESg", _attrs({"dn": f"{_ap_dn(dc)}/esg-{g['name']}", "name": g["name"]}))
             for g in _esgs(dc)]
    return flat + ep_selectors(dc)


def _nest(dc) -> dict:
    """Assemble the APIC MO tree (root ``polUni`` 'uni') from the flat inventory, parenting each MO by
    its DN — fvCEp under its fvAEPg, fvEPSelector under its fvESg, EPGs/ESGs under the fvAp, the AP
    under the tenant, the tenant under uni. Internal node = ``{cls, attrs, children}``."""
    root = {"cls": "polUni", "attrs": _attrs({"dn": "uni"}), "children": []}
    by_dn = {"uni": root}
    nodes = []
    for mo in _flat_mos(dc):
        cls = next(iter(mo))
        node = {"cls": cls, "attrs": dict(mo[cls]["attributes"]), "children": []}
        by_dn[node["attrs"].get("dn", "")] = node
        nodes.append(node)
    for node in nodes:
        parent_dn = node["attrs"].get("dn", "").rsplit("/", 1)[0]
        by_dn.get(parent_dn, root)["children"].append(node)
    return root


def _walk(node: dict):
    yield node
    for c in node["children"]:
        yield from _walk(c)


def _find(root: dict, dn: str):
    return next((n for n in _walk(root) if n["attrs"].get("dn") == dn), None)


def _render(node: dict, rsp: str) -> dict:
    """Internal node → wire MO. ``rsp-subtree`` controls nesting: ``no`` (default) → flat,
    ``children`` → direct children, ``full`` → the whole subtree nested."""
    if rsp == "children":
        kids = [_render(c, "no") for c in node["children"]]
    elif rsp == "full":
        kids = [_render(c, "full") for c in node["children"]]
    else:
        kids = None
    return _mo(node["cls"], node["attrs"], kids or None)


def mo_subtree(dc, dn_path: str, params: dict | None = None) -> list[dict]:
    """``GET /api/mo/<dn>`` — the controller's ``queryByDn`` — honoring the APIC query options the
    scanner actually sends: ``query-target`` (self|children|subtree), ``target-subtree-class`` (class
    filter), ``rsp-subtree`` (nesting). The scanner lists tenants with
    ``queryByDn('uni', query-target=children, target-subtree-class=fvTenant)``; returning the *whole*
    flat tree there (ignoring the filter) is why the Select-objects 'Tenants' list unmarshalled empty —
    CloudGuard expects only ``fvTenant`` back. A bare query (no options) stays permissive and returns
    the full subtree, so direct ``curl`` testing still sees everything."""
    params = params or {}
    dn = dn_path.rsplit(".", 1)[0] if dn_path.endswith((".json", ".xml")) else dn_path
    dn = dn.strip("/") or "uni"
    target = _find(_nest(dc), dn)
    if target is None:
        return []
    qt = (params.get("query-target") or "").lower()
    rsp = (params.get("rsp-subtree") or "no").lower()
    tsc = params.get("target-subtree-class")
    classes = {c.strip() for c in tsc.split(",")} if tsc else None
    if qt == "self":
        sel = [target]
    elif qt == "children":
        sel = list(target["children"])
    else:                                    # 'subtree' or a bare query → permissive full subtree
        sel = list(_walk(target))
    if classes is not None:
        sel = [n for n in sel if n["cls"] in classes]
    return [_render(n, rsp) for n in sel]


# --- auth (APIC login → APIC-cookie) --------------------------------------------------------

def auth_ok(dc, username: str, password: str) -> bool:
    cfg = (dc.content or {}).get("auth") or {}
    if not dc_creds.configured(cfg):
        return True
    return username == cfg.get("username") and bool(dc_creds.matches(cfg, password))


def authorized(dc, *, apic_cookie: str = "") -> bool:
    """Open when no creds configured; otherwise requires the APIC-cookie we issued at login."""
    cfg = (dc.content or {}).get("auth") or {}
    if not dc_creds.configured(cfg):
        return True
    return bool(apic_cookie)


def login_objects(username: str):
    """``aaaLogin`` managed object — the token CloudGuard reads (and echoes as the APIC-cookie)."""
    token = uuid.uuid4().hex
    return token, [_mo("aaaLogin", {
        "token": token, "refreshTimeoutSeconds": "600", "maximumLifetimeSeconds": "86400",
        "userName": username or "admin", "restTimeoutSeconds": "90"})]


def login_response(username: str):
    """JSON form of the login response (used by the .json path and the tests)."""
    token, objs = login_objects(username)
    return token, imdata(objs)


def forbidden_objs() -> list[dict]:
    return [_mo("error", {"code": "401", "text": "Authentication failed."})]


def forbidden() -> dict:
    """APIC error envelope (JSON) for a rejected request / bad credentials."""
    return imdata(forbidden_objs())
