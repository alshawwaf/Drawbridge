"""Build VMware NSX-T **Policy Mode** REST responses from a Datacenter's simulated inventory.

CloudGuard Controller (Policy Mode) imports Groups (NS Groups), Virtual Machines, and Tags. The
mock answers the handful of GETs the controller makes:
  - POST /api/session/create                                        (auth handshake)
  - GET  /policy/api/v1/infra/domains/default/groups                (groups + membership + tags)
  - GET  .../groups/{id}/members/virtual-machines                   (effective VM members)
  - GET  /policy/api/v1/infra/realized-state/virtual-machines       (VMs + tags, no IPs)
  - GET  /api/v1/fabric/vifs                                        (IPs, joined by owner_vm_id)
Tags are NSX-T {scope, tag} pairs. Every list endpoint uses the {"results":[...], "result_count":N}
envelope, so any unmodeled collection can safely return an empty list.
"""
import base64
import uuid

from ..security import verify_password

_NS = uuid.UUID("00000000-0000-0000-0000-00000000c0d2")


def _uuid(token: str, *parts: str) -> str:
    return str(uuid.uuid5(_NS, token + "/" + "/".join(parts)))


def _tag(s: str) -> dict:
    """Parse a 'scope=value' (or bare 'value') tag string into NSX-T's {scope, tag} shape."""
    s = (s or "").strip()
    if "=" in s:
        scope, _, tag = s.partition("=")
        return {"scope": scope.strip(), "tag": tag.strip()}
    return {"scope": "", "tag": s}


def _tag_value(t: dict) -> str:
    """NSX-T membership-condition value form: 'scope|tag' (or just 'tag' when scope is empty)."""
    return f"{t['scope']}|{t['tag']}" if t.get("scope") else t["tag"]


def _vms(dc) -> list[dict]:
    return (dc.content or {}).get("vms", []) or []


def _ips(vm: dict) -> list[str]:
    return vm.get("ips") or ([vm["ip"]] if vm.get("ip") else [])


def _gid(name: str) -> str:
    return name.strip().lower().replace(" ", "-")


def list_result(results: list) -> dict:
    """The standard NSX-T ListResult envelope — also the safe empty-collection response."""
    return {"results": results, "result_count": len(results)}


def virtual_machines(dc) -> dict:
    """Policy realized-state VM inventory: VMs + tags (IPs are on the VIFs — see vifs())."""
    res = []
    for vm in _vms(dc):
        ext = _uuid(dc.token, "vm", vm.get("name", ""))
        res.append({
            "resource_type": "VirtualMachine", "display_name": vm.get("name"),
            "external_id": ext, "power_state": "VM_RUNNING", "type": "REGULAR",
            "compute_ids": [f"externalId:{ext}"],
            "tags": [_tag(t) for t in (vm.get("tags") or [])],
        })
    return list_result(res)


def vifs(dc) -> dict:
    """Virtual interfaces — the only place VM IPs live; joined to a VM by owner_vm_id."""
    res = []
    for vm in _vms(dc):
        ips = _ips(vm)
        res.append({
            "resource_type": "VirtualNetworkInterface",
            "external_id": _uuid(dc.token, "vif", vm.get("name", "")),
            "owner_vm_id": _uuid(dc.token, "vm", vm.get("name", "")), "owner_vm_type": "REGULAR",
            "device_key": "4000",
            "ip_address_info": [{"source": "VM_TOOLS", "ip_addresses": ips}] if ips else [],
        })
    return list_result(res)


def domains(infra: str = "infra") -> dict:
    """The policy domains list. CloudGuard enumerates domains (`…/infra/domains`) before fetching
    each domain's groups, so the 'default' domain must be present or no groups are ever discovered.
    On the Global Manager (``infra='global-infra'``) CloudGuard renders each domain as a **Region**."""
    return list_result([{
        "resource_type": "Domain", "id": "default", "display_name": "default",
        "path": f"/{infra}/domains/default", "parent_path": f"/{infra}", "relative_path": "default",
        "marked_for_delete": False, "_protection": "NOT_PROTECTED", "_revision": 0,
    }])


def sites(dc, infra: str = "global-infra") -> dict:
    """Federation **Locations** (Global Manager only — ``/global-infra/sites``).

    The GM lists onboarded NSX sites here, and CloudGuard turns each into a **Region** (R82.10:
    *"regions are created automatically after you onboard locations in Global Manager"*). We return
    **one** Location so the Region is backed by a real site instead of an empty placeholder — which
    is what lets the global NS Groups nest under it: a global domain's objects only surface where the
    domain has *span*, and span comes from onboarded Locations. With a single Location everything
    spans it implicitly (CloudGuard makes no `/span` or `/domain-deployment-maps` call — confirmed
    from a full GM scan trace, whose entire cycle is domains + groups + sites). Shape follows the
    NSX-T policy Site object (``site_type`` ``ONPREM_LM``, path ``/{infra}/sites/<id>``).

    The site's system UUID (``unique_id``/``site_id``) is what each global Group references via its
    ``origin_site_id`` ("which site owns the object") so CloudGuard can place the group under this
    site's Region — see ``groups()``. Both carry the same deterministic UUID."""
    sid = _uuid(dc.token, "site", "default")
    return list_result([{
        "resource_type": "Site", "id": "default", "display_name": "default",
        "path": f"/{infra}/sites/default", "parent_path": f"/{infra}", "relative_path": "default",
        "site_type": "ONPREM_LM", "site_index": 0, "unique_id": sid, "site_id": sid,
        "marked_for_delete": False, "_protection": "NOT_PROTECTED", "_revision": 0,
    }])


def groups(dc, infra: str = "infra") -> dict:
    """NS Groups. ``infra`` is the policy path segment: ``infra`` for a Local Manager (NSX-T) or
    ``global-infra`` for the Global Manager (Global NSX-T).

    Each group carries a **``parent_path``** pointing at its domain (``/{infra}/domains/default``).
    A real NSX-T policy object always has this; on the Local Manager it's what files the group under
    its domain.

    On the **Global Manager** that wasn't enough: a trace showed the Site makes CloudGuard build a
    navigable Region (it drills in with ``GetDCNodeChildren rootId: region_id``), but the groups still
    didn't appear under it because nothing tied them to the site. The GM Group schema has **no inline
    ``span``** — instead every federated object carries **``origin_site_id``** ("which site owns the
    object"). So for the GM we stamp each group's ``origin_site_id`` with the Site's system UUID (see
    ``sites()``); that's the link CloudGuard uses to nest the group under that site's Region. (Not set
    on the LM, which has no Federation sites.)"""
    res = []
    domain_path = f"/{infra}/domains/default"
    site_owner = _uuid(dc.token, "site", "default") if infra == "global-infra" else None
    for g in (dc.content or {}).get("groups", []) or []:
        expr = []
        if g.get("member_tag"):
            expr.append({"resource_type": "Condition", "member_type": "VirtualMachine",
                         "key": "Tag", "operator": "EQUALS", "value": _tag_value(_tag(g["member_tag"]))})
        gid = _gid(g.get("name", ""))
        entry = {
            "id": gid, "display_name": g.get("name"), "resource_type": "Group",
            "path": f"{domain_path}/groups/{gid}", "parent_path": domain_path, "relative_path": gid,
            "expression": expr, "tags": [_tag(t) for t in (g.get("tags") or [])],
            "marked_for_delete": False, "_protection": "NOT_PROTECTED", "_revision": 0,
        }
        if site_owner:
            entry["origin_site_id"] = site_owner
        res.append(entry)
    return list_result(res)


def group_member_ips(dc, group_id: str) -> dict:
    """Effective member IP ADDRESSES of a group (Policy `.../members/ip-addresses`) — the IPs of the
    VMs whose tags satisfy the group's membership tag. This is how CloudGuard resolves a group to the
    IPs it enforces on (it calls this, NOT `.../members/virtual-machines`)."""
    g = next((x for x in ((dc.content or {}).get("groups", []) or [])
              if _gid(x.get("name", "")) == group_id), None)
    ips: list[str] = []
    if g and g.get("member_tag"):
        want = _tag(g["member_tag"])
        for vm in _vms(dc):
            if any(_tag(t) == want for t in (vm.get("tags") or [])):
                ips.extend(_ips(vm))
    return list_result(ips)


def group_members(dc, group_id: str) -> dict:
    """Effective VM members of a group — VMs whose tags satisfy the group's membership tag."""
    g = next((x for x in ((dc.content or {}).get("groups", []) or [])
              if _gid(x.get("name", "")) == group_id), None)
    res = []
    if g and g.get("member_tag"):
        want = _tag(g["member_tag"])
        for vm in _vms(dc):
            if any(_tag(t) == want for t in (vm.get("tags") or [])):
                res.append({"resource_type": "RealizedVirtualMachine",
                            "id": _uuid(dc.token, "vm", vm.get("name", "")),
                            "display_name": vm.get("name"), "power_state": "VM_RUNNING",
                            "state": "REALIZED"})
    return list_result(res)


# --- auth -------------------------------------------------------------------------------

def auth_ok(dc, username: str, password: str) -> bool:
    """Validate credentials against the datacenter's configured ones; permissive if none set."""
    cfg = (dc.content or {}).get("auth") or {}
    if not cfg.get("password_hash"):
        return True
    return username == cfg.get("username") and verify_password(password, cfg["password_hash"])


def authorized(dc, *, authorization: str = "", jsessionid: str = "") -> bool:
    """A request is authorized when no creds are configured (open lab), or it carries valid
    Basic auth, or a session cookie we issued after a validated /api/session/create."""
    cfg = (dc.content or {}).get("auth") or {}
    if not cfg.get("password_hash"):
        return True
    if authorization.lower().startswith("basic "):
        try:
            user, _, pw = base64.b64decode(authorization[6:]).decode("utf-8").partition(":")
            return auth_ok(dc, user, pw)
        except Exception:
            return False
    return bool(jsessionid)


def forbidden() -> dict:
    """NSX-T's error body shape for a rejected request."""
    return {"httpStatus": "FORBIDDEN", "error_code": 403, "module_name": "common-services",
            "error_message": "The credentials were incorrect or the account is locked."}
