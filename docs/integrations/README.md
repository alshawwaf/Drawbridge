# Integrations

Each integration makes the portal **act as the external system Check Point integrates with**, so a
PoV can be demoed end-to-end without the real thing. Three interaction models:

- **Pull** — Check Point polls/scans the portal: the **feeds** and the **datacenter** API mocks.
- **Push** — the portal pushes to the gateway's Gaia API: **Dynamic Layers**.
- **Manage** — the portal acts as a `web_api` / Gaia **client to a real R82.10 SMS or gateway** (read-only
  except an explicit, dry-run-first apply): view + export policy as IaC
  ([Management API export](management-export.md)), export a box's **Gaia OS** config
  ([Gaia export](gaia-export.md)), and turn a ticket into a rule
  ([Access Automation](access-automation.md)). Drive it from agents/HTTP clients via the
  **[MCP server + REST API](../mcp-n8n.md)**; runtime config, secrets, and API keys live in
  **[Settings](../settings.md)**.

To *drive* the pull model live during a demo, see **[Scenarios](scenarios.md)** — mutate a DC's
inventory (flip a tag, scale out, run a timed preset) and the next ~30s scan re-resolves policy.

| Integration | Mocks | Check Point object | Where you point it |
|---|---|---|---|
| [Generic Data Center](generic-datacenter.md) | sk167210 JSON server | Generic Data Center | `https://<portal>/gdc/<token>.json` |
| [Network Feed](network-feed.md) | feed server (list / JSON+JQ) | Network Feed | `https://<portal>/netfeed/<token>` |
| [IoC Feed](ioc-feed.md) | Custom Intelligence — CSV / STIX 1.x / Custom CSV / Snort | Threat Prevention (Anti-Bot / AV / IPS) | `https://<portal>/ioc/<token>.{csv,xml,txt}` |
| [OpenStack](openstack.md) | Keystone + Nova + Neutron | Data Center → OpenStack | `https://<portal>/openstack/<token>/v3` |
| [VMware vCenter](vcenter.md) | vSphere SOAP + REST | Data Center → vCenter | bare host (apex) — `<portal>` |
| [VMware NSX-T](nsxt.md) | NSX-T Policy Mode REST (Local Manager) | Data Center → NSX-T | bare host (apex) — `<portal>` |
| [VMware Global NSX-T](global-nsxt.md) | NSX-T Global Manager / Federation | Data Center → Global NSX-T | bare host (apex) — `<portal>` |
| [Proxmox VE](proxmox.md) | Proxmox `/api2/json` REST | Data Center → Proxmox | bare host **+ `:443`** (apex) — `<portal>:443` |
| [Cisco ACI](aci.md) | APIC REST — **XML** (`aaaLogin` + class queries) | Data Center → Cisco ACI | bare host (apex) — `https://<portal>` |
| [Kubernetes](kubernetes.md) | kube-apiserver REST (bearer token) | Data Center → Kubernetes | full **URL** (apex) — `https://<portal>` |
| [Nutanix Prism](nutanix.md) | Prism REST v3 + v4 (Basic auth) | Data Center → Nutanix | bare host (apex) — `<portal>` **on port 9440** (connector-fixed) |
| [Dynamic Layers](dynamic-layers.md) | Gaia API (`set-dynamic-content`) | *(push to gateway / mock)* | n/a — portal is the client |
| [Scenarios](scenarios.md) | live inventory mutation + timed presets | *(drives any DC mock's next poll)* | n/a — portal control panel (`/scenarios`) |
| [SIEM receiver](siem.md) | Log Exporter sink — syslog / CEF / LEEF / JSON over TCP+UDP | *(gateway / MGMT sends logs here)* | `udp+tcp://<portal-host>:5514` (not HTTP — bypasses Caddy) |

## Routing: path-based vs apex single-tenant

The Check Point **Hostname/URL** field decides how a mock is addressed:

- **Path-based (token in URL)** — OpenStack and the feeds accept a full URL, so the token lives in the
  path and you can run **many** of each per portal.
- **Apex single-tenant** — vCenter, NSX-T, Proxmox, and **Cisco ACI** are served at the portal **root**
  and resolve the **most-recently-created** DC of that provider. Limit: **one each per portal**. (Token
  routes are kept for debugging.) vCenter/NSX-T accept only a bare host; Proxmox also needs an explicit
  **`:443`** (its field defaults to 8006); ACI accepts a full URL but its client **uses only the host**
  (it discards the path), so it lands at the apex too.

## Full inventory is required

Every datacenter mock must expose **all** the object types CloudGuard imports for that provider, and
**group-type objects must resolve to member IPs** (vCenter tag → VMs, OpenStack security group →
instances, NSX-T NS group → VMs). An empty group object reads as a broken integration in a PoV.
Check the provider's importable types in the **R82.10** admin guide (the deployed version — always
read the latest, never older) before declaring it done.

## Credentials

Auth on a DC mock is optional (leave it blank for an open lab). When set, it's **encrypted at rest
(AES-256-GCM, `DCSIM_ENCRYPTION_KEY`, falls back to the session secret)** — so the DC page can show the
password / token-secret back as a **copyable, masked field** to paste into SmartConsole. Where the
encryption key or library is unavailable the app falls back to a one-way hash (the value then can't be
shown). Feed auth (Custom Header for the Generic DC feed, HTTP Basic for Network / IoC feeds) is stored
for comparison and is likewise copyable on the feed page. Credentials are always masked in the Activity
log.

## Shared diagnostics

- **Activity log** (`/activity`) — every inbound call (feed poll, datacenter API, mock Gaia) with the
  request/response bodies, redacted. Filter by kind; `/sdk` rows are labeled with the SOAP op. This is
  the first place to look when something doesn't sync.
- **"All 200s but still initializing"** = a topology / referential-integrity problem, not a missing
  endpoint — make ids cross-reference correctly.
- **Management side:** `$FWDIR/log/cloud_proxy.elg` (a.k.a. `vsec.elg`) logs the CloudGuard scanner.
- After fixing a datacenter mock, **delete + re-add** the DC object in SmartConsole to force a clean
  full sync (it caches the prior topology).

## Supported CloudGuard R82.10 datacenter types

Endpoint-configurable (mockable here): OpenStack ✅, vCenter ✅, NSX-T ✅ (+ Global NSX-T), Nutanix,
Cisco ACI, Kubernetes, Proxmox (new), Cisco ISE. Fixed-cloud (**not** mockable — use a Generic Data
Center feed instead): AWS, Azure, GCP, Oracle OCI. Dropped in R82.10: NSX-V, Nuage.
