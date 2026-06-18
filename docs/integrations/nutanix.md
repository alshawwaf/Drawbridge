# Nutanix Prism (Data Center mock)

Mocks **Nutanix Prism** so CloudGuard Controller R82.10 imports the cluster's **VMs** (with NIC IPs)
and **Categories** (Prism's key/value tags), and resolves a category to the VMs carrying it.

- Service: [`app/services/nutanix.py`](../../app/services/nutanix.py)
- Router: [`app/routers/nutanix_mock.py`](../../app/routers/nutanix_mock.py)

> **Status:** Built to the **decompiled scanner contract** (`cms.jar` →
> `com/checkpoint/datacenter/scanner/nutanix`), serving **both Prism v3 and v4**. Verified end-to-end
> via TestClient (v3 POST + v4 GET + Basic auth). Pending first live-CloudGuard confirmation.

## Decompiled contract (what CloudGuard actually does)

From `NutanixScanner` + `NutanixApi` + `NutanixDeployment` and the `objects`/`v4objects` models:

- **Auth:** HTTP **Basic** (`Authorization: Basic <base64(user:pass)>`).
- **Version:** CloudGuard probes **v4** first (`GET /api/vmm/v4.1/ahv/config/vms?$limit=1`) and falls
  back to **v3**; both are modeled so either path works.
- **Endpoints —**
  - v3: `POST /api/nutanix/v3/vms/list`, `POST /api/nutanix/v3/categories/list`,
    `POST /api/nutanix/v3/categories/{name}/list`, `POST /api/nutanix/v3/category/query`,
    `GET /api/nutanix/v3/users/me`.
  - v4: `GET /api/vmm/v4.1/ahv/config/vms`, `GET /api/prism/v4.1/config/categories`.
- **Tree (scanner methods):** `updateRoot` → `updateVMsV3/V4` + `updateCategoriesV3/V4` +
  `createCategoryHierarchy` (a **Key** repository → **Value** folders → the VMs tagged `key=value`, via
  `buildCategoryAssociations` / `addVmToCategory`). So a category value resolves to its VMs' IPs.
- **Model fields —** v3: VM `{metadata{uuid,categories}, status{name,description,resources{nic_list[]
  {ip_endpoint_list[]{ip}}}}}`; v4: VM `{extId,name,description,nics[]{networkInfo{ipv4Info{
  learnedIpAddresses[]{value}}}},categories[]{extId}}`, Category `{extId,key,value}`; v4 list
  `{data[],metadata{totalAvailableResults,hasMorePages}}`.

## Configure in SmartConsole

Apex single-tenant (bare host) — **one Nutanix mock per portal**.

> ⚠️ **Nutanix needs the portal reachable on port 9440** (see Gotchas). Its Hostname field takes a
> **bare** host/IP only (a scheme or `:port` is rejected with *"must be a valid IP address or DNS
> name"*), and the connector hardcodes **Prism Central's 9440**. So unlike every other DC type, 443
> alone isn't enough — expose the portal on 9440 first (the bundled `docker-compose.yml` + `Caddyfile`
> now do this; for a Dokploy/Traefik host add a 9440 TLS entrypoint, or a `socat` 9440→443 passthrough).

1. Portal → **Data Centers → New → Nutanix**. Add VMs (`name = ip | Category=Value, …`); optionally set
   Prism credentials.
2. SmartConsole → **New → More → Cloud → Data Center → Nutanix…**
   - **Hostname:** the **bare** host — `dcsim.ai.alshawwaf.ca` (no `https://`, no port; CloudGuard hits
     `:9440` itself).
   - **Username / Password:** the Basic-auth credentials you set on the portal DC (Viewer role is enough).
3. **Test Connection → Select objects.**

## Endpoints served (apex)

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/nutanix/v3/users/me` | the whoami (connection check) |
| `POST` | `/api/nutanix/v3/vms/list` | VMs (`status.resources.nic_list[].ip_endpoint_list[].ip` + `metadata.categories`) |
| `POST` | `/api/nutanix/v3/categories/list` | category keys |
| `POST` | `/api/nutanix/v3/categories/{name}/list` | a key's values |
| `POST` | `/api/nutanix/v3/category/query` | VM references for the requested `key=value` (associations) |
| `GET` | `/api/vmm/v4.1/ahv/config/vms` | v4 VMs (`nics[].networkInfo.ipv4Info.learnedIpAddresses[]`) |
| `GET` | `/api/prism/v4.1/config/categories` | v4 categories (`{extId,key,value}`) |

Token routes `/nutanix/<token>/api/...` are kept for direct testing. The `/api/nutanix`, `/api/vmm`,
`/api/prism` prefixes are unique — no overlap with the NSX-T/K8s/ACI apex paths.

## Object model (portal input)

VMs only: `name = ip | Category=Value, Category=Value`. The pipe part is the VM's **Categories** (Prism
key/value tags). Category keys/values and the VM↔category associations are all derived from these — a
category value resolves to the VMs carrying it (how CloudGuard enforces policy on a category).

## Auth

Basic credentials set on the portal DC are stored only as a one-way hash and validated on every call
(`401` on mismatch). Leave them blank for an open lab.

## Gotchas / pending

- **Port 9440 (the one real gotcha)** — the connector hardcodes Prism Central's **9440** for the cert
  fetch + API (`Failed to get certificate from <host>:9440 … Connection timed out`), and the Hostname
  field rejects any `:port` or scheme, so you **cannot** point it at 443 like the others. The portal
  must listen on 9440 with the same cert: the bundled `docker-compose.yml`/`Caddyfile` publish 9440;
  on a Dokploy/Traefik host add a 9440 TLS entrypoint routing the domain → the app, **or** run a raw
  passthrough `socat TCP-LISTEN:9440,fork,reuseaddr TCP:127.0.0.1:443` (the TLS+SNI flows to Traefik
  on 443). Then enter the bare hostname.
- **v4 vs v3** — both are served, so it works whichever CloudGuard picks; the v4 probe is
  `…/ahv/config/vms?$limit=1`.
- First-cut to the decompiled contract; any call beyond these is in the
  [Activity log](/activity?kind=datacenter) (filter → Data Center → Nutanix) to model next. After a
  change, **delete + re-add** the object in SmartConsole so it re-syncs.
