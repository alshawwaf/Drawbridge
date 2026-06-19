"""Build Kubernetes (kube-apiserver) **REST** responses from a Datacenter's simulated inventory.

CloudGuard Controller R82.10's Kubernetes scanner imports **Nodes, Pods, Services, Endpoints** and the
**Namespaces** + **Labels** derived from them. It authenticates with a service-account **bearer token**
(``Authorization: Bearer <token>``) over TLS. Confirmed from the decompiled scanner (cms.jar
``com/checkpoint/datacenter/scanner/kubernetes``): ``KubernetesScanner`` builds ``updateNamespaceTree``
/ ``updateNodeTree`` / ``updatePodTree`` / ``updateServicesTree`` / ``updateEndpointTree`` + a Label
view; ``KubernetesApiRest`` calls ``GET /api`` then ``GET /api/{version}/{nodes,pods,services,
endpoints}``. Namespaces are NOT a fetched endpoint — the scanner derives them from each object's
``metadata.namespace`` (``mapNamespaceToIps`` resolves a namespace to all its pod IPs).

Response shapes are standard kube-apiserver: a ``*List`` envelope
``{"kind","apiVersion":"v1","items":[…]}``; each object ``{"metadata":{name,namespace,uid,labels},…}``;
Node IPs in ``status.addresses[]`` (``type:"InternalIP"``), Pod IP in ``status.podIP``, Service IP in
``spec.clusterIP``, Endpoints IPs in ``subsets[].addresses[].ip``. The decompiled model fields:
Metadata{name,namespace,uid,labels}, Node{metadata,status}, NodeAddress{type,address},
Pod{metadata,status}, Service{metadata,spec,status}, ServiceSpec{type,clusterIP}, Endpoint{metadata,
subsets}, Subset{addresses}, EndpointAddress{ip}.
"""
import base64
import json
import socket
import ssl
import uuid

from . import dc_creds

_NS_DEFAULT = "default"


def portal_tls_chain_pem(host: str, port: int = 443) -> str:
    """The portal's own served TLS certificate chain (leaf + intermediates + root) as a PEM bundle, for
    the user to import into SmartConsole's **CA Certificate** field. The Kubernetes connector builds a
    custom trust store (``DomainKeyStore`` / ``isCertificateTrustedFromCA``) and won't trust the
    portal's cert without it, so the TLS handshake fails before any HTTP — unlike the other connectors,
    which use the default Java trust store. Fetched with an unverified context (we only need the certs
    the server presents, not to verify them)."""
    ctx = ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=8) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ss:
            chain = list(ss.get_unverified_chain() or []) if hasattr(ss, "get_unverified_chain") else []
    pems = [ssl.DER_cert_to_PEM_cert(der) for der in chain]
    if not pems:                                          # fallback: at least the leaf
        pems = [ssl.get_server_certificate((host, port))]
    return "".join(p if p.endswith("\n") else p + "\n" for p in pems)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def sa_token(dc) -> str:
    """A deterministic, well-formed Kubernetes **service-account JWT** for this datacenter — the portal
    serves it for download so the user imports it into SmartConsole's required 'Service Account Token'
    field (the connector takes the token as a FILE, and ``decodeToken``s it, so it must be a valid JWT).
    The mock IS the API server, so the signature isn't cryptographically verified — it only needs valid
    JWT structure; the signature is derived from the DC token so it's stable and unique per DC."""
    header = {"alg": "RS256", "kid": "dcsim", "typ": "JWT"}
    payload = {"iss": "kubernetes/serviceaccount",
               "kubernetes.io/serviceaccount/namespace": "kube-system",
               "kubernetes.io/serviceaccount/secret.name": "cloudguard-token",
               "kubernetes.io/serviceaccount/service-account.name": "cloudguard",
               "sub": "system:serviceaccount:kube-system:cloudguard"}
    sig = _b64u(f"dcsim-mock-{getattr(dc, 'token', '') or 'open'}".encode())
    return f"{_b64u(json.dumps(header).encode())}.{_b64u(json.dumps(payload).encode())}.{sig}"
_UID_NS = uuid.UUID("00000000-0000-0000-0000-00000000babe")   # stable uids across calls


def _uid(*parts: str) -> str:
    return str(uuid.uuid5(_UID_NS, "/".join(parts)))


def _pods(dc) -> list[dict]:
    return (dc.content or {}).get("pods", []) or []


def _nodes(dc) -> list[dict]:
    return (dc.content or {}).get("nodes", []) or []


def _services(dc) -> list[dict]:
    return (dc.content or {}).get("services", []) or []


def namespaces(dc) -> list[str]:
    """Distinct namespaces, derived from the pods' and services' ``metadata.namespace`` (the scanner
    builds the Namespace tree this way — there is no ``/namespaces`` endpoint)."""
    seen: list[str] = []
    for o in _pods(dc) + _services(dc):
        ns = o.get("namespace") or _NS_DEFAULT
        if ns not in seen:
            seen.append(ns)
    return seen or [_NS_DEFAULT]


def _meta(name: str, namespace: str | None = None, labels: dict | None = None) -> dict:
    m = {"name": name, "uid": _uid(namespace or "_", name), "labels": labels or {},
         "resourceVersion": "1", "creationTimestamp": "2024-01-01T00:00:00Z"}
    if namespace:
        m["namespace"] = namespace
    return m


def _list(kind: str, items: list[dict]) -> dict:
    return {"kind": kind, "apiVersion": "v1", "metadata": {"resourceVersion": "1"}, "items": items}


def api_versions() -> dict:
    """``GET /api`` — core API group version discovery (the scanner reads ``versions`` and then calls
    ``/api/<version>/…``)."""
    return {"kind": "APIVersions", "versions": ["v1"],
            "serverAddressByClientCIDRs": [{"clientCIDR": "0.0.0.0/0", "serverAddress": ""}]}


def nodes(dc) -> dict:
    """``GET /api/v1/nodes`` — cluster nodes with their InternalIP."""
    items = []
    for n in _nodes(dc):
        ip = n.get("ip")
        addrs = ([{"type": "InternalIP", "address": ip}] if ip else []) + \
                [{"type": "Hostname", "address": n.get("name")}]
        items.append({"metadata": _meta(n.get("name"), labels=n.get("labels") or {}),
                      "status": {"addresses": addrs}})
    return _list("NodeList", items)


def pods(dc) -> dict:
    """``GET /api/v1/pods`` — pods with their podIP, namespace and labels (the namespace + label trees
    are built from these)."""
    items = []
    for p in _pods(dc):
        ip = p.get("ip")
        items.append({
            "metadata": _meta(p.get("name"), p.get("namespace") or _NS_DEFAULT, p.get("labels") or {}),
            "status": {"phase": "Running", "podIP": ip or "", "podIPs": [{"ip": ip}] if ip else []},
        })
    return _list("PodList", items)


def services(dc) -> dict:
    """``GET /api/v1/services`` — services with their clusterIP and type."""
    items = []
    for s in _services(dc):
        cip = s.get("cluster_ip") or ""
        items.append({
            "metadata": _meta(s.get("name"), s.get("namespace") or _NS_DEFAULT, s.get("labels") or {}),
            "spec": {"type": s.get("type") or "ClusterIP", "clusterIP": cip,
                     "clusterIPs": [cip] if cip else [], "ports": []},
            "status": {"loadBalancer": {}},
        })
    return _list("ServiceList", items)


def endpoints(dc) -> dict:
    """``GET /api/v1/endpoints`` — one Endpoints per service; addresses = the pod IPs in that service's
    namespace (how CloudGuard resolves a Service to its backing pod IPs)."""
    items = []
    for s in _services(dc):
        ns = s.get("namespace") or _NS_DEFAULT
        ips = [p["ip"] for p in _pods(dc)
               if (p.get("namespace") or _NS_DEFAULT) == ns and p.get("ip")]
        items.append({"metadata": _meta(s.get("name"), ns),
                      "subsets": [{"addresses": [{"ip": ip} for ip in ips]}] if ips else []})
    return _list("EndpointsList", items)


# --- auth (service-account bearer token) ----------------------------------------------------

def _bearer(authorization: str) -> str:
    s = (authorization or "").strip()
    return s[7:].strip() if s[:7].lower() == "bearer " else ""


def auth_ok(dc, authorization: str) -> bool:
    """Validate the bearer token against the datacenter's configured one; permissive if none set."""
    cfg = (dc.content or {}).get("auth") or {}
    if not dc_creds.configured(cfg, "token"):
        return True                                   # open lab — accept any (or no) token
    token = _bearer(authorization)
    return bool(token) and bool(dc_creds.matches(cfg, token, "token"))


def authorized(dc, authorization: str = "") -> bool:
    return auth_ok(dc, authorization)


def unauthorized() -> dict:
    """kube-apiserver 401 — a ``Status`` object."""
    return {"kind": "Status", "apiVersion": "v1", "status": "Failure", "reason": "Unauthorized",
            "code": 401, "message": "Unauthorized"}
