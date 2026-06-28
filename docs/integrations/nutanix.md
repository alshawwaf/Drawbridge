# Nutanix Prism (Data Center mock)

Mocks **Nutanix Prism** so CloudGuard Controller R82.10 imports the cluster's **VMs** (with NIC IPs)
and **Categories** (Prism's key/value tags), and resolves a category to the VMs carrying it.

- Service: [`app/services/nutanix.py`](../../app/services/nutanix.py)
- Router: [`app/routers/nutanix_mock.py`](../../app/routers/nutanix_mock.py)

> **Status:** ✅ **Confirmed live against CloudGuard Controller R82.10 (2026-06-19)** — Test Connection
> succeeds and the object viewer imports VMs + Categories (folders for each category Key, VMs under
> `/VMs`). Built to the **decompiled scanner contract** (`cms.jar` →
> `com/checkpoint/datacenter/scanner/nutanix`), serving **both Prism v3 and v4**.

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
   - **Hostname:** the **bare** host — `dcsim.example.com` (no `https://`, no port; CloudGuard hits
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

Basic credentials set on the portal DC are **encrypted at rest (AES-256-GCM)** and validated on every
call (`401` on mismatch); the DC page can show the password back as a copyable masked field. Leave
them blank for an open lab.

## Gotchas / pending

- **Port 9440 (the one real gotcha)** — the connector hardcodes Prism Central's **9440** for the cert
  fetch + API (`Failed to get certificate from <host>:9440 … Connection timed out`), and the Hostname
  field rejects any `:port` or scheme, so you **cannot** point it at 443 like the others. The portal
  must be reachable on 9440 with the same cert — that's **three layers** (host listener + host firewall
  + the cloud/CloudShare edge); see *Exposing port 9440 end-to-end* below. The **edge** is the one that
  bites: 443 is published there but 9440 isn't, so the SMS's connection dies at the perimeter even when
  the host is perfect.
- **v4 vs v3** — both are served, so it works whichever CloudGuard picks; the v4 probe is
  `…/ahv/config/vms?$limit=1`.
- **Pagination (the v4 trap that stalls the object viewer).** CloudGuard pages the v4 list endpoints
  with `$page`/`$limit`. The mock **must slice** to the requested page and report `hasMorePages`
  honestly — returning the full list on every page makes the scanner loop forever on categories and
  **never reach the VMs**, so *Select objects* sits on **"Loading…"** (you'll see thousands of identical
  `…/config/categories` calls in the Activity log, all 200). Connectivity looks perfect; nothing loads.
  Fixed in `nutanix.py` (`page_limit` + a slicing `_v4_envelope`) and regression-tested
  (`tests/test_nutanix.py::test_v4_pagination_terminates`).
- First-cut to the decompiled contract; any call beyond these is in the
  [Activity log](/activity?kind=datacenter) (filter → Data Center → Nutanix) to model next. After a
  change, **delete + re-add** the object in SmartConsole so it re-syncs.

## Exposing port 9440 end-to-end (Dokploy/Traefik + cloud edge)

The hosted `dcsim.example.com` runs behind Dokploy's Traefik (TLS on 443 → the app; it ignores the
repo's `docker-compose.yml`/`Caddyfile`). Nutanix needs `:9440` reachable **all the way from the SMS**,
which is **three layers** — and every one must be open (confirmed the hard way against a live SMS):

**1. A listener for 9440 on the host.** A raw TCP passthrough is simplest — the TLS + SNI flow straight
to Traefik on 443, which serves the real cert and routes to the app (no cert handling, no app change):
```bash
docker run -d --name dcsim-nutanix-9440 --restart unless-stopped --network host \
  alpine/socat TCP-LISTEN:9440,fork,reuseaddr TCP:127.0.0.1:443
sudo ss -tlnp 'sport = :9440'      # confirm: socat LISTEN 0.0.0.0:9440
```
(Alternatively a proper Traefik `:9440` entrypoint + a router for the domain.)

**2. The host firewall.**
```bash
sudo ufw allow 9440/tcp
sudo ufw status | grep 9440        # confirm: 9440/tcp ALLOW
```
> ⚠️ `ufw status` listing the rule is **not** proof it's enforced. If `sudo ufw reload` says *"Firewall
> not enabled"*, the rules never loaded — usually a stray line after `COMMIT` in `/etc/ufw/after.rules`
> (remove it, then `sudo ufw disable && sudo ufw enable`). And a `DOCKER-USER` deny-by-default lockdown
> in `after.rules` can drop external→container 9440 even with ufw allowing it — which is exactly why the
> 9440 listener in step 1 is a **host-network** socat (it never takes the guarded forward path). Both
> traps bit this lab; the full ladder is in [siem.md → Troubleshooting](siem.md).

**3. The cloud / hosting edge — the layer people miss.** Whatever publishes `:443` to the internet must
also pass `:9440`. 443 works only because the edge forwards it; 9440 stays dropped until you add it.
- **Generic cloud (AWS/Azure/GCP/OCI):** add inbound **TCP 9440** to the VM's security group / NSG /
  firewall rule, same source as the existing 443 rule.
- **CloudShare** (this lab's host): the environment edge publishes standard ports (80/443) only — open
  9440 in the environment's networking/policy (often needs the CloudShare account admin). If that's not
  possible, point the Nutanix DC at the portal VM's **internal** address so 9440 stays inside the
  CloudShare environment and never hits the public edge. (The TLS cert is issued for the public FQDN, so
  the internal name must resolve to / match it — Nutanix fetches the cert before anything else.)

**Verify from a public host** (not the VM's own LAN, or the host firewall masks the result):
```bash
curl -skI https://dcsim.example.com:9440/healthz   # a response (not a timeout) = all 3 layers open
```
Then in SmartConsole enter the **bare** hostname (`dcsim.example.com`) → Test Connection.

> **Status (2026-06-19): ✅ working end-to-end on `YUL-SKUNK`** — Test Connection passes and the object
> viewer imports the VMs + Categories. Beyond opening 9440 at all three layers, the real blockers were
> (1) a **host-firewall trap** — `ufw` in a zombie state (a stray line after `COMMIT` in `after.rules`
> stopped it loading) plus a `DOCKER-USER` deny-by-default that dropped external→container traffic, so a
> direct/host-mode publish failed and the **host-network socat** in step 1 was required; and (2) the
> **v4 pagination loop** (see Gotchas) that left the viewer on "Loading…". Both fixed. Full firewall
> diagnostic ladder: [siem.md → Troubleshooting](siem.md).
