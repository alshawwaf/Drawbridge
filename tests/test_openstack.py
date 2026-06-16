"""OpenStack mock: Keystone catalog points back at the portal; Nova/Neutron shapes correct."""
from app.routers.datacenters import parse_instances, parse_subnets
from app.services import openstack as os_mock


class _DC:
    def __init__(self, token, content):
        self.token = token
        self.content = content


DC = _DC("tok123", {
    "instances": [{"name": "web-1", "ip": "10.0.0.11", "tags": ["web", "prod"]}],
    "subnets": [{"name": "app", "cidr": "10.0.0.0/24"}],
    "security_groups": [{"name": "web-sg"}],
})


def test_keystone_catalog_points_back_at_portal():
    subject, body = os_mock.keystone_token(DC, "https://portal.example")
    assert subject  # X-Subject-Token issued
    cat = {s["type"]: s for s in body["token"]["catalog"]}
    assert cat["compute"]["endpoints"][0]["url"] == "https://portal.example/openstack/tok123/nova/v2.1"
    assert cat["network"]["endpoints"][0]["url"] == "https://portal.example/openstack/tok123/neutron"
    assert cat["identity"]["endpoints"][0]["url"] == "https://portal.example/openstack/tok123/v3"


def test_keystone_projects_lists_the_scoped_project():
    body = os_mock.keystone_projects(DC, "https://portal.example")
    assert len(body["projects"]) == 1
    p = body["projects"][0]
    assert p["name"] == "demo" and p["enabled"] is True and p["domain_id"] == "default"
    # the project id must equal the tenant_id used by Nova/Neutron, or scoping finds nothing
    assert p["id"] == os_mock.nova_servers(DC)["servers"][0]["tenant_id"]
    assert body["links"]["self"].endswith("/openstack/tok123/v3/auth/projects")


def test_nova_servers_shape():
    server = os_mock.nova_servers(DC)["servers"][0]
    assert server["name"] == "web-1"
    assert server["addresses"]["private"][0]["addr"] == "10.0.0.11"
    assert server["tags"] == ["web", "prod"]


def test_neutron_subnets_and_secgroups():
    assert os_mock.neutron_subnets(DC)["subnets"][0]["cidr"] == "10.0.0.0/24"
    assert os_mock.neutron_security_groups(DC)["security_groups"][0]["name"] == "web-sg"


def test_parse_instances_with_tags():
    out = parse_instances("web-1 = 10.0.0.11 | web, prod\ndb-1 = 10.0.0.21")
    assert out[0] == {"name": "web-1", "ip": "10.0.0.11", "tags": ["web", "prod"]}
    assert out[1] == {"name": "db-1", "ip": "10.0.0.21", "tags": []}


def test_parse_subnets():
    assert parse_subnets("app = 10.0.0.0/24")[0] == {"name": "app", "cidr": "10.0.0.0/24"}
