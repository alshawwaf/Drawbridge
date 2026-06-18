"""Kubernetes mock: api discovery, node/pod/service/endpoint shapes, derived namespaces, bearer auth."""
from app.middleware import _kind
from app.routers.datacenters import parse_k8s_nodes, parse_k8s_pods, parse_k8s_services
from app.security import hash_password
from app.services import kubernetes as k8s


class _DC:
    def __init__(self, content):
        self.token = "tok-k8s"
        self.content = content


DC = _DC({
    "nodes": [{"name": "node-1", "ip": "10.40.0.11", "labels": {}}],
    "pods": [{"namespace": "production", "name": "web-1", "ip": "10.40.1.11", "labels": {"app": "web"}},
             {"namespace": "production", "name": "api-1", "ip": "10.40.1.21", "labels": {"app": "api"}},
             {"namespace": "default", "name": "db-0", "ip": "10.40.2.11", "labels": {"app": "db"}}],
    "services": [{"namespace": "production", "name": "web-svc", "cluster_ip": "10.40.10.1",
                  "type": "LoadBalancer"}],
})


def test_api_versions():
    v = k8s.api_versions()
    assert v["kind"] == "APIVersions" and "v1" in v["versions"]


def test_list_envelope_is_kube_apiserver_shape():
    p = k8s.pods(DC)
    assert p["kind"] == "PodList" and p["apiVersion"] == "v1" and isinstance(p["items"], list)


def test_nodes_carry_internal_ip():
    n = k8s.nodes(DC)["items"][0]
    assert n["metadata"]["name"] == "node-1"
    assert any(a["type"] == "InternalIP" and a["address"] == "10.40.0.11" for a in n["status"]["addresses"])


def test_pods_carry_ip_namespace_labels():
    items = k8s.pods(DC)["items"]
    assert {p["metadata"]["namespace"] for p in items} == {"production", "default"}
    web = next(p for p in items if p["metadata"]["name"] == "web-1")
    assert web["status"]["podIP"] == "10.40.1.11" and web["metadata"]["labels"]["app"] == "web"


def test_services_carry_clusterip_and_type():
    s = k8s.services(DC)["items"][0]
    assert s["spec"]["clusterIP"] == "10.40.10.1" and s["spec"]["type"] == "LoadBalancer"


def test_endpoints_resolve_to_namespace_pod_ips():
    e = next(x for x in k8s.endpoints(DC)["items"] if x["metadata"]["name"] == "web-svc")
    ips = [a["ip"] for sub in e["subsets"] for a in sub["addresses"]]
    assert set(ips) == {"10.40.1.11", "10.40.1.21"}      # production pods only — not the default-ns db


def test_namespaces_derived_from_objects():
    assert set(k8s.namespaces(DC)) == {"production", "default"}


def test_bearer_token_auth():
    secured = _DC({"auth": {"token_hash": hash_password("sa-token-xyz")}})
    assert k8s.auth_ok(secured, "Bearer sa-token-xyz") is True
    assert k8s.auth_ok(secured, "Bearer wrong") is False
    assert k8s.auth_ok(secured, "") is False
    assert k8s.auth_ok(DC, "anything") is True           # open lab — no token configured


def test_parsers():
    pods = parse_k8s_pods("production/web-1 = 10.40.1.11 | app=web, tier=frontend\ndb-0 = 10.40.2.11")
    assert pods[0] == {"namespace": "production", "name": "web-1", "ip": "10.40.1.11",
                       "labels": {"app": "web", "tier": "frontend"}}
    assert pods[1]["namespace"] == "default"             # bare name → default namespace
    assert parse_k8s_nodes("node-1 = 10.40.0.11")[0] == {"name": "node-1", "ip": "10.40.0.11", "labels": {}}
    svcs = parse_k8s_services("production/web-svc = 10.40.10.1 | LoadBalancer\ndefault/db = 10.40.10.2")
    assert svcs[0]["type"] == "LoadBalancer" and svcs[1]["type"] == "ClusterIP"


def test_sa_token_is_a_wellformed_deterministic_jwt():
    import base64
    import json
    t = k8s.sa_token(DC)
    parts = t.split(".")
    assert len(parts) == 3                                # header.payload.signature
    def _dec(p):
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    assert _dec(parts[0])["typ"] == "JWT"
    assert _dec(parts[1])["iss"] == "kubernetes/serviceaccount"
    assert k8s.sa_token(DC) == t                          # deterministic (stable per DC)
    other = _DC({}); other.token = "different-token"
    assert k8s.sa_token(other) != t                       # varies per DC


def test_middleware_classifies_k8s_as_datacenter():
    assert _kind("/api/v1/nodes") == "datacenter"
    assert _kind("/api") == "datacenter"                 # version discovery
    assert _kind("/k8s/tok/api/v1/pods") == "datacenter"
    # must not steal the NSX-T family's shared apex paths
    assert _kind("/api/session/create") == "datacenter"
