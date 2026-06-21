"""Build Proxmox VE **REST** (``/api2/json``) responses from a Datacenter's simulated inventory.

CloudGuard Controller R82.10 ships a new Proxmox scanner. It imports **VMs** (with IPs read from the
qemu-guest-agent), **Nodes**, an optional **Cluster**, and **Tags**. It authenticates with a Proxmox
**API token** sent on every request as ``Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>``
(role needs ``Sys.Audit``/``VM.Audit``/``VM.Monitor``). Every Proxmox response is wrapped in
``{"data": ...}``.

This is the first cut, built to the documented endpoints + the Proxmox API shape; the exact calls
CloudGuard makes are confirmed from the portal Activity log and the responses tuned to match.
"""
from . import dc_creds

_NODE = "pve"  # single-node cluster — Clusters are optional for single-node setups (per R82.10 doc)


def _vms(dc) -> list[dict]:
    return (dc.content or {}).get("vms", []) or []


def _ips(vm: dict) -> list[str]:
    return vm.get("ips") or ([vm["ip"]] if vm.get("ip") else [])


def _node_name(dc) -> str:
    return (dc.content or {}).get("node") or _NODE


def _node_ip(dc) -> str:
    """The Proxmox node's management IP (imported as the Node object's IP). Configurable; defaulted."""
    return (dc.content or {}).get("node_ip") or "10.20.0.10"


def _indexed(dc) -> list[tuple[int, dict]]:
    """(vmid, vm) pairs. vmid is synthesized as 100+position so it's stable across calls."""
    return [(100 + i, vm) for i, vm in enumerate(_vms(dc))]


def _tags(vm: dict) -> str:
    """Proxmox tags are a single ``;``-joined string (flat, no scope), e.g. ``web;prod``."""
    return ";".join(t for t in (vm.get("tags") or []) if t)


def data(payload):
    """The Proxmox API envelope — every response body is ``{"data": ...}``."""
    return {"data": payload}


def version() -> dict:
    return data({"version": "8.3.0", "release": "8.3", "repoid": "dcsim"})


def _vm_resource(vmid: int, vm: dict, node: str) -> dict:
    return {"id": f"qemu/{vmid}", "type": "qemu", "vmid": vmid, "name": vm.get("name"),
            "node": node, "status": "running", "template": 0, "tags": _tags(vm),
            "maxcpu": 2, "maxmem": 4294967296, "maxdisk": 34359738368, "uptime": 3600}


def _node_resource(node: str) -> dict:
    return {"id": f"node/{node}", "type": "node", "node": node, "status": "online",
            "maxcpu": 8, "maxmem": 33554432000, "uptime": 86400, "level": ""}


def cluster_resources(dc, rtype: str = "") -> dict:
    """``GET /cluster/resources[?type=vm]`` — cluster-wide inventory (nodes + VMs in one call)."""
    node = _node_name(dc)
    vms = [_vm_resource(vmid, vm, node) for vmid, vm in _indexed(dc)]
    nodes_ = [_node_resource(node)]
    if rtype == "vm":
        return data(vms)
    if rtype == "node":
        return data(nodes_)
    return data(nodes_ + vms)


def nodes(dc) -> dict:
    """``GET /nodes`` — the node list."""
    return data([{"node": _node_name(dc), "status": "online", "type": "node",
                  "maxcpu": 8, "maxmem": 33554432000, "uptime": 86400}])


def cluster_status(dc) -> dict:
    """``GET /cluster/status`` — cluster quorum + the node(s) with their **IPs**. CloudGuard reads
    this to establish the Node tree (R82.10 imports Nodes with IPs); an empty response here leaves the
    VMs with no node to nest under, so the Select-objects tree stays empty. Confirmed from the trace:
    CloudGuard calls this and we were returning the catch-all's empty list."""
    node = _node_name(dc)
    return data([
        {"id": "cluster", "type": "cluster", "name": "dcsim", "version": 1, "quorate": 1, "nodes": 1},
        {"id": f"node/{node}", "type": "node", "name": node, "nodeid": 1, "online": 1, "local": 1,
         "ip": _node_ip(dc), "level": ""},
    ])


def node_qemu(dc, node: str) -> dict:
    """``GET /nodes/{node}/qemu`` — the QEMU VMs on a node."""
    return data([{"vmid": vmid, "name": vm.get("name"), "status": "running", "tags": _tags(vm),
                  "maxmem": 4294967296, "cpus": 2, "uptime": 3600}
                 for vmid, vm in _indexed(dc) if _node_name(dc) == node])


def _find_vm(dc, vmid: int):
    return next((vm for vid, vm in _indexed(dc) if vid == vmid), None)


def agent_interfaces(dc, vmid: int) -> dict:
    """``GET /nodes/{node}/qemu/{vmid}/agent/network-get-interfaces`` — the qemu-guest-agent view,
    the ONLY place a VM's IP comes from. CloudGuard skips loopback (and won't get an IP if the VM is
    off or has no agent)."""
    vm = _find_vm(dc, vmid)
    result = [{"name": "lo", "hardware-address": "00:00:00:00:00:00",
               "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4", "prefix": 8}]}]
    ips = _ips(vm) if vm else []
    if ips:
        result.append({"name": "eth0", "hardware-address": "02:00:00:00:00:01",
                       "ip-addresses": [{"ip-address": ip,
                                         "ip-address-type": "ipv6" if ":" in ip else "ipv4",
                                         "prefix": 64 if ":" in ip else 24}
                                        for ip in ips]})
    return data({"result": result})


def qemu_config(dc, vmid: int) -> dict:
    """``GET /nodes/{node}/qemu/{vmid}/config`` — served defensively (VM detail)."""
    vm = _find_vm(dc, vmid)
    if not vm:
        return data({})
    return data({"name": vm.get("name"), "tags": _tags(vm), "cores": 2, "memory": 4096,
                 "agent": "1", "net0": "virtio=02:00:00:00:00:01,bridge=vmbr0"})


def pools(dc) -> dict:
    """``GET /pools`` — empty for the single-node lab (pools are optional)."""
    return data([])


# --- auth (Proxmox API token) ---------------------------------------------------------------

def _parse_token(authorization: str):
    """Pull ``(token_id, secret)`` out of a ``PVEAPIToken=user@realm!tokenid=secret`` Authorization
    value. Returns ``(None, None)`` when it isn't a PVEAPIToken header."""
    s = (authorization or "").strip()
    low = s.lower()
    if "pveapitoken=" not in low:
        return None, None
    s = s[low.index("pveapitoken=") + len("pveapitoken="):]
    token_id, sep, secret = s.partition("=")          # token_id has no '=', secret is the UUID
    return (token_id.strip(), secret.strip()) if sep else (None, None)


def auth_ok(dc, authorization: str) -> bool:
    """Validate the API token against the datacenter's configured one; permissive if none set."""
    cfg = (dc.content or {}).get("auth") or {}
    if not dc_creds.configured(cfg, "secret"):
        return True                                   # open lab — accept any (or no) token
    token_id, secret = _parse_token(authorization)
    if not token_id:
        return False
    return token_id == cfg.get("token_id") and bool(dc_creds.matches(cfg, secret, "secret"))


def authorized(dc, authorization: str = "") -> bool:
    return auth_ok(dc, authorization)


def ticket(username: str) -> dict:
    """``POST /access/ticket`` (password flow) — served defensively. CloudGuard uses an API token, so
    this is rarely called; we return a well-formed ticket so a password-based probe still succeeds."""
    return data({"ticket": "PVE:dcsim@pam:00000000", "CSRFPreventionToken": "00000000:dcsim",
                 "username": username or "dcsim@pam"})


def unauthorized() -> dict:
    """Proxmox returns 401 with no data on a bad/missing token."""
    return {"data": None}
