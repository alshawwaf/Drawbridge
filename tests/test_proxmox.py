"""Proxmox VE mock: cluster/resources VMs + node, qemu-guest-agent IPs, flat tags, API-token auth."""
from app.middleware import _kind
from app.routers.datacenters import parse_instances
from app.security import hash_password
from app.services import proxmox


class _DC:
    def __init__(self, token, content):
        self.token = token
        self.content = content


DC = _DC("tok-pve", {
    "vms": [
        {"name": "web-1", "ip": "10.20.0.11", "tags": ["web", "prod"]},
        {"name": "db-1", "ip": "10.20.0.21", "tags": ["db"]},
    ],
    "node": "pve",
})


def test_data_envelope():
    assert proxmox.data([1, 2]) == {"data": [1, 2]}


def test_cluster_resources_type_vm_lists_qemu_with_flat_tags():
    vms = proxmox.cluster_resources(DC, "vm")["data"]
    assert {v["name"] for v in vms} == {"web-1", "db-1"}
    web = next(v for v in vms if v["name"] == "web-1")
    assert web["type"] == "qemu" and web["vmid"] == 100 and web["node"] == "pve"
    assert web["status"] == "running" and web["tags"] == "web;prod"  # Proxmox tags: ';'-joined


def test_cluster_resources_unfiltered_includes_the_node():
    res = proxmox.cluster_resources(DC)["data"]
    assert {"node", "qemu"} <= {r["type"] for r in res}
    node = next(r for r in res if r["type"] == "node")
    assert node["node"] == "pve" and node["status"] == "online"


def test_agent_interfaces_returns_the_vm_ip_on_eth0():
    result = proxmox.agent_interfaces(DC, 100)["data"]["result"]
    names = {i["name"] for i in result}
    assert "lo" in names and "eth0" in names                      # loopback present; CloudGuard skips it
    eth0 = next(i for i in result if i["name"] == "eth0")
    assert eth0["ip-addresses"][0]["ip-address"] == "10.20.0.11"  # web-1 (vmid 100)


def test_node_qemu_lists_the_nodes_vms():
    vms = proxmox.node_qemu(DC, "pve")["data"]
    assert {v["name"] for v in vms} == {"web-1", "db-1"}
    assert all("vmid" in v for v in vms)


def test_auth_validates_token_only_when_configured():
    secured = _DC("a", {"vms": [], "auth": {"token_id": "root@pam!cloudguard",
                                             "secret_hash": hash_password("s3cr3t")}})
    good = "PVEAPIToken=root@pam!cloudguard=s3cr3t"
    assert proxmox.authorized(secured, good) is True
    assert proxmox.authorized(secured, "PVEAPIToken=root@pam!cloudguard=wrong") is False
    assert proxmox.authorized(secured, "PVEAPIToken=other@pam!x=s3cr3t") is False
    assert proxmox.authorized(secured, "") is False                # configured, nothing presented
    assert proxmox.authorized(DC, "") is True                      # no token set = open lab


def test_parse_token_extracts_id_and_secret():
    assert proxmox._parse_token("PVEAPIToken=root@pam!cloudguard=abc-123") == \
        ("root@pam!cloudguard", "abc-123")
    assert proxmox._parse_token("Basic xyz") == (None, None)


def test_vms_reuse_the_name_ip_tags_parser():
    out = parse_instances("web-1 = 10.20.0.11 | web, prod")
    assert out == [{"name": "web-1", "ip": "10.20.0.11", "tags": ["web", "prod"]}]


def test_middleware_classifies_proxmox_as_datacenter():
    assert _kind("/api2/json/cluster/resources") == "datacenter"
    assert _kind("/proxmox/tok/api2/json/version") == "datacenter"
