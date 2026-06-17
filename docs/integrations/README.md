# Integrations

Each integration makes the portal **act as the external system Check Point integrates with**, so a
PoV can be demoed end-to-end without the real thing. Two interaction models:

- **Pull** — Check Point polls/scans the portal: the **feeds** and the **datacenter** API mocks.
- **Push** — the portal pushes to the gateway's Gaia API: **Dynamic Layers**.

| Integration | Mocks | Check Point object | Where you point it |
|---|---|---|---|
| [Generic Data Center](generic-datacenter.md) | sk167210 JSON server | Generic Data Center | `https://<portal>/gdc/<token>.json` |
| [Network Feed](network-feed.md) | feed server (list / JSON+JQ) | Network Feed | `https://<portal>/netfeed/<token>` |
| [OpenStack](openstack.md) | Keystone + Nova + Neutron | Data Center → OpenStack | `https://<portal>/openstack/<token>/v3` |
| [VMware vCenter](vcenter.md) | vSphere SOAP + REST | Data Center → vCenter | bare host (apex) — `<portal>` |
| [VMware NSX-T](nsxt.md) | NSX-T Policy Mode REST (Local Manager) | Data Center → NSX-T | bare host (apex) — `<portal>` |
| [VMware Global NSX-T](global-nsxt.md) | NSX-T Global Manager / Federation | Data Center → Global NSX-T | bare host (apex) — `<portal>` |
| [Dynamic Layers](dynamic-layers.md) | Gaia API (`set-dynamic-content`) | *(push to gateway / mock)* | n/a — portal is the client |

## Routing: path-based vs apex single-tenant

The Check Point **Hostname/URL** field decides how a mock is addressed:

- **Path-based (token in URL)** — OpenStack and the feeds accept a full URL, so the token lives in the
  path and you can run **many** of each per portal.
- **Apex single-tenant** — vCenter and NSX-T accept only a **bare host** (no scheme/path), so those
  mocks are served at the portal **root** and resolve the **most-recently-created** DC of that
  provider. Limit: **one vCenter and one NSX-T per portal**. (Token routes are kept for debugging.)

## Full inventory is required

Every datacenter mock must expose **all** the object types CloudGuard imports for that provider, and
**group-type objects must resolve to member IPs** (vCenter tag → VMs, OpenStack security group →
instances, NSX-T NS group → VMs). An empty group object reads as a broken integration in a PoV.
Check the provider's importable types in the R82 admin guide before declaring it done.

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
