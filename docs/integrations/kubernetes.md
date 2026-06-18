# Kubernetes (Data Center mock)

Mocks a **Kubernetes API server** (`kube-apiserver`) so CloudGuard Controller R82.10 imports the
cluster's **Nodes, Pods, Services, Endpoints** and the **Namespaces** + **Labels** derived from them.

- Service: [`app/services/kubernetes.py`](../../app/services/kubernetes.py)
- Router: [`app/routers/kubernetes_mock.py`](../../app/routers/kubernetes_mock.py)

> **Status:** Built to the **decompiled scanner contract** (`cms.jar` →
> `com/checkpoint/datacenter/scanner/kubernetes`), not guessed. Verified end-to-end via TestClient,
> including apex coexistence with the NSX-T family. Pending first live-CloudGuard confirmation.

## Decompiled contract (what CloudGuard actually does)

From `KubernetesScanner` + `KubernetesApiRest` + the `kubernetes.api.objects` model classes:

- **Auth:** service-account **bearer token** — `Authorization: Bearer <token>` — over TLS (CA cert).
- **Endpoints (the only ones called):**
  - `GET /api` → version discovery (`{"kind":"APIVersions","versions":["v1"]}`); the scanner then uses
    `/api/<version>/…`.
  - `GET /api/v1/nodes`, `GET /api/v1/pods`, `GET /api/v1/services`, `GET /api/v1/endpoints`.
- **Tree built (scanner methods):** `updateNamespaceTree`, `updateNodeTree`, `updatePodTree`,
  `updateServicesTree`, `updateEndpointTree`, plus `addToLabelView` (a **Label** view). **Namespaces are
  NOT a fetched endpoint** — the scanner derives them from each object's `metadata.namespace`
  (`mapNamespaceToIps` resolves a Namespace to all its pod IPs).
- **Model fields read:** `metadata{name, namespace, uid, labels}`, Node `status.addresses[]{type,
  address}` (IP = `InternalIP`), Pod `status.podIP`, Service `spec{type, clusterIP}`, Endpoints
  `subsets[].addresses[].ip`.

## Configure in SmartConsole

Apex single-tenant (bare host) — **one Kubernetes mock per portal**.

1. Portal → **Data Centers → New → Kubernetes**. Add Pods (`namespace/name = ip | labels`), Nodes, and
   Services; optionally set a bearer token.
2. On the portal DC page, download **both** files (buttons there): **⬇ Service Account Token** and
   **⬇ CA Certificate** (the portal's own TLS chain).
3. SmartConsole → **New → More → Cloud → Data Center → Kubernetes…**
   - **Hostname / API server:** the portal's host **with `:443`** (e.g. `dcsim.ai.alshawwaf.ca:443`).
     The kube-apiserver default is **6443**; the portal answers on 443, so the port must be 443.
   - **Import Service Account Token…:** pick the token file (required field — token is a file, not typed).
   - **CA Certificate:** **tick the box** and **Import CA Certificate…** → the `.pem`. **Required** —
     unlike the other connectors (which use Java's default trust store), the K8s connector builds its
     own (`DomainKeyStore`) and won't trust the portal's cert without it; the TLS handshake fails
     before any HTTP (a *"connection has failed / make sure the server is running"* error, even though
     `curl` to the same host works).
4. **Test Connection → Select objects.**

## Endpoints served (apex)

- `GET /api` → `APIVersions` (`versions:["v1"]`)
- `GET /api/v1/nodes` → `NodeList` (each node's `InternalIP`)
- `GET /api/v1/pods` → `PodList` (`status.podIP`, `metadata.namespace`, `metadata.labels`)
- `GET /api/v1/services` → `ServiceList` (`spec.clusterIP`, `spec.type`)
- `GET /api/v1/endpoints` → `EndpointsList` (one per service; addresses = pod IPs in that namespace)

Token routes `/k8s/<token>/api/...` are kept for direct testing.

**Routing note:** `/api/v1/...` is shared with the NSX-T family mock (which has an `/api/v1/{rest}`
catch-all). The Kubernetes paths are explicit and `kubernetes_mock` is registered **before**
`nsxt_mock`, so `/api/v1/nodes|pods|services|endpoints` + `GET /api` resolve to Kubernetes while NSX-T's
own paths (`/api/session`, `/api/v1/fabric/vifs`, the catch-all) fall through to it. A portal can run a
Kubernetes **and** an NSX-T DC at the same host.

## Object model (portal input)

- **Pods:** `namespace/name = podIP | label=val, label=val` (bare `name` → `default` namespace). The
  **Namespace** tree and **Label** view are built from these; a Namespace resolves to all its pods' IPs.
- **Nodes:** `name = ip` (cluster-scoped; IP = `InternalIP`).
- **Services:** `namespace/name = clusterIP | type` (`type` defaults to `ClusterIP`). Each service's
  `/endpoints` resolves to the pod IPs in its namespace.

## Auth

SmartConsole's Kubernetes object requires the service-account token as an **imported file** (not a
typed field), and decodes it — so it must be a well-formed JWT. The portal generates a deterministic,
valid per-DC token (download button on the DC page → `GET /datacenters/{id}/k8s-token`). The mock is
the API server and accepts it (open lab). TLS uses the portal's own (public) certificate, so the
optional **CA Certificate** import can stay unchecked.

## Gotchas / pending

- **Port `:443`** — the API server default is 6443; the hostname field must carry `:443` or CloudGuard
  won't reach the portal (same pattern as Proxmox's 8006).
- **Namespaces aren't fetched** — they're derived from pods/services. A pod with no `namespace/` prefix
  lands in `default`.
- First-cut to the decompiled contract; if a live scan calls anything beyond the five endpoints it's in
  the [Activity log](/activity?kind=datacenter) (filter → Data Center → Kubernetes) to model next.
- After a change, **delete + re-add** the object in SmartConsole so it re-syncs.
