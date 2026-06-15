"""Build OpenStack API responses (Keystone v3 token + service catalog, Nova servers, Neutron
subnets/security-groups/networks/ports) from a Datacenter's simulated inventory.

The Keystone catalog points back at the portal's own mock Nova/Neutron endpoints (token-scoped),
so Check Point follows the catalog exactly as it would against a real OpenStack cloud.
"""
import uuid

_NS = uuid.UUID("00000000-0000-0000-0000-0000000c0de1")
_EXPIRES = "2035-01-01T00:00:00.000000Z"
_ISSUED = "2020-01-01T00:00:00.000000Z"


def _id(*parts: str) -> str:
    return str(uuid.uuid5(_NS, "/".join(parts)))


def _ips(inst: dict) -> list[str]:
    if inst.get("ips"):
        return inst["ips"]
    return [inst["ip"]] if inst.get("ip") else []


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


def nova_servers(dc) -> dict:
    servers = []
    for i, inst in enumerate(dc.content.get("instances", []) or []):
        name = inst.get("name") or f"instance-{i + 1}"
        addrs = [{"addr": ip, "version": 6 if ":" in ip else 4, "OS-EXT-IPS:type": "fixed",
                  "OS-EXT-IPS-MAC:mac_addr": "fa:16:3e:%02x:%02x:%02x" % (i, i, i)} for ip in _ips(inst)]
        servers.append({
            "id": _id(dc.token, "server", name), "name": name, "status": "ACTIVE",
            "tenant_id": _id(dc.token, "project"), "user_id": _id(dc.token, "user"),
            "addresses": {"private": addrs},
            "metadata": inst.get("metadata", {}) or {},
            "tags": inst.get("tags", []) or [],
            "security_groups": [{"name": g} for g in (inst.get("security_groups") or ["default"])],
            "OS-EXT-AZ:availability_zone": "nova",
            "OS-EXT-STS:vm_state": "active",
        })
    return {"servers": servers}


def neutron_subnets(dc) -> dict:
    out = []
    for i, s in enumerate(dc.content.get("subnets", []) or []):
        name = s.get("name") or f"subnet-{i + 1}"
        cidr = s.get("cidr", "")
        out.append({"id": _id(dc.token, "subnet", name), "name": name, "cidr": cidr,
                    "ip_version": 6 if ":" in cidr else 4, "enable_dhcp": True,
                    "network_id": _id(dc.token, "network", "default"),
                    "tenant_id": _id(dc.token, "project"), "project_id": _id(dc.token, "project")})
    return {"subnets": out}


def neutron_security_groups(dc) -> dict:
    out = []
    for i, g in enumerate(dc.content.get("security_groups", []) or []):
        name = g.get("name") if isinstance(g, dict) else str(g)
        name = name or f"sg-{i + 1}"
        out.append({"id": _id(dc.token, "sg", name), "name": name,
                    "description": (g.get("description", "") if isinstance(g, dict) else ""),
                    "tenant_id": _id(dc.token, "project"), "project_id": _id(dc.token, "project"),
                    "security_group_rules": []})
    return {"security_groups": out}


def neutron_networks(dc) -> dict:
    subnet_ids = [_id(dc.token, "subnet", (s.get("name") or f"subnet-{i + 1}"))
                  for i, s in enumerate(dc.content.get("subnets", []) or [])]
    return {"networks": [{"id": _id(dc.token, "network", "default"), "name": "default-net",
                          "status": "ACTIVE", "admin_state_up": True, "subnets": subnet_ids,
                          "tenant_id": _id(dc.token, "project"), "project_id": _id(dc.token, "project")}]}


def neutron_ports(dc) -> dict:
    out = []
    default_subnet = _id(dc.token, "subnet", "default")
    for i, inst in enumerate(dc.content.get("instances", []) or []):
        name = inst.get("name") or f"instance-{i + 1}"
        out.append({"id": _id(dc.token, "port", name), "name": "", "status": "ACTIVE",
                    "device_id": _id(dc.token, "server", name),
                    "fixed_ips": [{"ip_address": ip, "subnet_id": default_subnet} for ip in _ips(inst)],
                    "tenant_id": _id(dc.token, "project")})
    return {"ports": out}
