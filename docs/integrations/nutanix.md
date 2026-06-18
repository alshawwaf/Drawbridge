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

1. Portal → **Data Centers → New → Nutanix**. Add VMs (`name = ip | Category=Value, …`); optionally set
   Prism credentials.
2. SmartConsole → **New → More → Cloud → Data Center → Nutanix…**
   - **Prism address:** the portal's host **with `:443`** (e.g. `dcsim.ai.alshawwaf.ca:443`). Prism
     Central defaults to **9440**; the portal answers on 443, so the port must be 443.
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

- **Port `:443`** — Prism Central defaults to 9440; the address field must carry `:443` (same pattern
  as Proxmox 8006 / Kubernetes 6443).
- **v4 vs v3** — both are served, so it works whichever CloudGuard picks; the v4 probe is
  `…/ahv/config/vms?$limit=1`.
- First-cut to the decompiled contract; any call beyond these is in the
  [Activity log](/activity?kind=datacenter) (filter → Data Center → Nutanix) to model next. After a
  change, **delete + re-add** the object in SmartConsole so it re-syncs.
