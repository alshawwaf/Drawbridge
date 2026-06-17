"""Build OpenStack API responses (Keystone v3 token + service catalog, Nova servers, Neutron
subnets/security-groups/networks/ports) from a Datacenter's simulated inventory.

The Keystone catalog points back at the portal's own mock Nova/Neutron endpoints (token-scoped),
so Check Point follows the catalog exactly as it would against a real OpenStack cloud.
"""
import ipaddress
import uuid

from ..security import verify_password

_NS = uuid.UUID("00000000-0000-0000-0000-0000000c0de1")
_EXPIRES = "2035-01-01T00:00:00.000000Z"
_ISSUED = "2020-01-01T00:00:00.000000Z"
_NETWORK_NAME = "default-net"  # the single mock network; VM addresses are keyed by this name


def _subnets(dc) -> list[dict]:
    """The datacenter's subnets as {id, name, cidr} — the canonical ids ports/networks reference."""
    out = []
    for i, s in enumerate(dc.content.get("subnets", []) or []):
        name = s.get("name") or f"subnet-{i + 1}"
        out.append({"id": _id(dc.token, "subnet", name), "name": name, "cidr": s.get("cidr", "")})
    return out


def _subnet_for_ip(dc, subnets: list[dict], ip: str) -> str:
    """The id of the subnet whose CIDR contains ip; falls back to the first subnet."""
    for s in subnets:
        try:
            if ip and s["cidr"] and ipaddress.ip_address(ip) in ipaddress.ip_network(s["cidr"], strict=False):
                return s["id"]
        except ValueError:
            continue
    return subnets[0]["id"] if subnets else _id(dc.token, "subnet", "default")


def _id(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "/".join(parts)))


def _ips(inst: dict) -> list[str]:
    if inst.get("ips"):
        return inst["ips"]
    return [inst["ip"]] if inst.get("ip") else []


def _instance_sgs(inst: dict) -> list[str]:
    """The security-group names an instance belongs to. For OpenStack the instance's '| ...' list IS
    its security-group membership (CloudGuard imports SGs, not Nova tags), so each SG object resolves
    to the IPs of its member instances."""
    return inst.get("security_groups") or inst.get("tags") or []


def _secgroup_names(dc) -> list[str]:
    """Every security group to expose: those explicitly defined, plus any referenced by an instance
    (so a group an instance joins always exists as an object, and explicit groups can be empty)."""
    names: list[str] = []
    for g in (dc.content.get("security_groups") or []):
        name = (g.get("name") if isinstance(g, dict) else str(g)) or ""
        if name and name not in names:
            names.append(name)
    for inst in (dc.content.get("instances") or []):
        for name in _instance_sgs(inst):
            if name and name not in names:
                names.append(name)
    return names


def keystone_token(dc, base_url: str, *, user: str = "admin", project: str = "demo") -> tuple[str, dict]:
    """Return (X-Subject-Token, response body). Catalog endpoints point at this portal."""
    base = f"{base_url.rstrip('/')}/openstack/{dc.token}"

    def service(stype: str, name: str, path: str) -> dict:
        return {
            "type": stype, "name": name, "id": _id(dc.token, stype),
            "endpoints": [
                {"id": _id(dc.token, stype, iface), "interface": iface, "region": "RegionOne",
                 "region_id": "RegionOne", "url": f"{base}{path}"}
                for iface in ("public", "internal", "admin")
            ],
        }

    body = {"token": {
        "methods": ["password"],
        "expires_at": _EXPIRES, "issued_at": _ISSUED, "audit_ids": ["dcsim-mock"],
        "user": {"id": _id(dc.token, "user"), "name": user, "password_expires_at": None,
                 "domain": {"id": "default", "name": "Default"}},
        "project": {"id": _id(dc.token, "project"), "name": project,
                    "domain": {"id": "default", "name": "Default"}},
        "roles": [{"id": _id(dc.token, "role"), "name": "admin"}, {"id": _id(dc.token, "member"), "name": "member"}],
        "catalog": [
            service("identity", "keystone", "/v3"),
            service("compute", "nova", "/nova/v2.1"),
            service("network", "neutron", "/neutron"),
        ],
    }}
    return uuid.uuid4().hex, body


def keystone_projects(dc, base_url: str, *, project: str = "demo") -> dict:
    """Projects available to the authenticated token (Keystone GET /v3/auth/projects).
    CloudGuard calls this right after auth to discover which projects to scan — without it the
    controller reports the Data Center as 'still initializing'. The project id matches the
    tenant/project id used by every Nova/Neutron resource, so scoping resolves the inventory."""
    base = f"{base_url.rstrip('/')}/openstack/{dc.token}"
    pid = _id(dc.token, "project")
    return {
        "projects": [{
            "id": pid, "name": project, "domain_id": "default", "enabled": True,
            "is_domain": False, "parent_id": "default", "description": "dcsim mock project",
            "tags": [], "links": {"self": f"{base}/v3/projects/{pid}"},
        }],
        "links": {"self": f"{base}/v3/auth/projects", "previous": None, "next": None},
    }


def keystone_error_401() -> dict:
    """The Keystone body for a rejected login — so SmartConsole shows an auth error,
    not the generic 'still initializing'."""
    return {"error": {"code": 401, "title": "Unauthorized",
                      "message": "The request you have made requires authentication."}}


def configured_project(dc, fallback: str = "demo") -> str:
    return ((dc.content or {}).get("auth") or {}).get("project") or fallback


def auth_ok(dc, username: str, password: str) -> bool:
    """True when the presented credentials match the datacenter's configured ones. If no
    credentials are configured, the mock stays permissive (legacy / quick-lab datacenters)."""
    cfg = (dc.content or {}).get("auth") or {}
    if not cfg.get("password_hash"):
        return True
    return username == cfg.get("username") and verify_password(password, cfg["password_hash"])


def nova_servers(dc) -> dict:
    servers = []
    for i, inst in enumerate(dc.content.get("instances", []) or []):
        name = inst.get("name") or f"instance-{i + 1}"
        addrs = [{"addr": ip, "version": 6 if ":" in ip else 4, "OS-EXT-IPS:type": "fixed",
                  "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:%02x:%02x:%02x" % (i, i, i)} for ip in _ips(inst)]
        servers.append({
            "id": _id(dc.token, "server", name), "name": name, "status": "ACTIVE",
            "tenant_id": _id(dc.token, "project"), "user_id": _id(dc.token, "user"),
            "addresses": {_NETWORK_NAME: addrs},  # keyed by the network name, as real Nova does
            "metadata": inst.get("metadata", {}) or {},
            "tags": inst.get("tags", []) or [],
            "security_groups": [{"name": g} for g in (_instance_sgs(inst) or ["default"])],
            "OS-EXT-AZ:availability_zone": "nova",
            "OS-EXT-STS:vm_state": "active",
        })
    return {"servers": servers}


def neutron_subnets(dc) -> dict:
    net_id = _id(dc.token, "network", "default")
    out = []
    for s in _subnets(dc):
        out.append({"id": s["id"], "name": s["name"], "cidr": s["cidr"],
                    "ip_version": 6 if ":" in s["cidr"] else 4, "enable_dhcp": True,
                    "network_id": net_id,
                    "tenant_id": _id(dc.token, "project"), "project_id": _id(dc.token, "project")})
    return {"subnets": out}


def neutron_security_groups(dc) -> dict:
    """Every security group (explicit + instance-referenced), each with an id that ports/servers
    reference so CloudGuard resolves the group to its member instances' IPs. A default egress rule
    is included for realism."""
    pid = _id(dc.token, "project")
    out = []
    for name in _secgroup_names(dc):
        sid = _id(dc.token, "sg", name)
        out.append({
            "id": sid, "name": name, "description": f"{name} security group",
            "tenant_id": pid, "project_id": pid,
            "security_group_rules": [
                {"id": _id(dc.token, "sgr", name, "egress"), "security_group_id": sid,
                 "direction": "egress", "ethertype": "IPv4", "protocol": None,
                 "remote_ip_prefix": None, "remote_group_id": None,
                 "port_range_min": None, "port_range_max": None,
                 "tenant_id": pid, "project_id": pid},
            ],
        })
    return {"security_groups": out}


def neutron_networks(dc) -> dict:
    subnet_ids = [_id(dc.token, "subnet", (s.get("name") or f"subnet-{i + 1}"))
                  for i, s in enumerate(dc.content.get("subnets", []) or [])]
    return {"networks": [{"id": _id(dc.token, "network", "default"), "name": "default-net",
                          "status": "ACTIVE", "admin_state_up": True, "subnets": subnet_ids,
                          "tenant_id": _id(dc.token, "project"), "project_id": _id(dc.token, "project")}]}


def neutron_floatingips(dc) -> dict:
    """Floating IPs (Neutron). This mock models private addressing only, so the list is empty —
    but CloudGuard enumerates floating IPs during import, so we must answer with an empty list
    rather than a 404 (which would stall the import)."""
    return {"floatingips": []}


def neutron_ports(dc) -> dict:
    """One port per instance, fully linked: network_id -> the network, fixed_ips.subnet_id -> the
    real subnet the IP belongs to, device_id -> the server. Without these links the controller
    can fetch everything (200s) yet never assemble the topology — the 'still initializing' symptom."""
    out = []
    subs = _subnets(dc)
    net_id = _id(dc.token, "network", "default")
    for i, inst in enumerate(dc.content.get("instances", []) or []):
        name = inst.get("name") or f"instance-{i + 1}"
        fixed = [{"ip_address": ip, "subnet_id": _subnet_for_ip(dc, subs, ip)} for ip in _ips(inst)]
        out.append({
            "id": _id(dc.token, "port", name), "name": "", "status": "ACTIVE",
            "network_id": net_id, "device_id": _id(dc.token, "server", name),
            "device_owner": "compute:nova", "admin_state_up": True,
            "mac_address": "fa:16:3e:%02x:%02x:%02x" % (i & 0xff, (i >> 8) & 0xff, (i + 1) & 0xff),
            "fixed_ips": fixed,
            "security_groups": [_id(dc.token, "sg", n) for n in _instance_sgs(inst)],
            "tenant_id": _id(dc.token, "project"), "project_id": _id(dc.token, "project"),
        })
    return {"ports": out}
