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


def groups(dc) -> dict:
    res = []
    for g in (dc.content or {}).get("groups", []) or []:
        expr = []
        if g.get("member_tag"):
            expr.append({"resource_type": "Condition", "member_type": "VirtualMachine",
                         "key": "Tag", "operator": "EQUALS", "value": _tag_value(_tag(g["member_tag"]))})
        gid = _gid(g.get("name", ""))
        res.append({
            "id": gid, "display_name": g.get("name"), "resource_type": "Group",
            "path": f"/infra/domains/default/groups/{gid}", "expression": expr,
            "tags": [_tag(t) for t in (g.get("tags") or [])],
        })
    return list_result(res)


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
