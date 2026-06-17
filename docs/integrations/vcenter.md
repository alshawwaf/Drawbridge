# VMware vCenter (Data Center mock)

Mocks a real **VMware vCenter** so CloudGuard Controller imports a full inventory tree — Datacenter →
Cluster → Hosts + Virtual Machines — plus vCenter **Tags**, and resolves VMs to live IPs for policy.

This is the most involved mock: CloudGuard's vCenter connector (Apache CXF) speaks **two** APIs at once.

| Layer | API | Serves |
|---|---|---|
| Handshake + inventory | **SOAP** vSphere Web Services (`/sdk`) | version negotiate → `RetrieveServiceContent` → `Login` → PropertyCollector inventory |
| Session + tags | **REST** vSphere Automation (`/rest/com/vmware/cis/…`) | session token + the tagging service |

- Service: [`app/services/vsphere.py`](../../app/services/vsphere.py)
- Router: [`app/routers/vcenter_mock.py`](../../app/routers/vcenter_mock.py)

## Configure in SmartConsole

The vCenter **Hostname** field accepts only a **bare host** (no scheme, no path), so this mock is
served at the portal **apex** (root) and resolves the **most-recently-created** vCenter DC — i.e.
**one vCenter mock per portal**.

1. Portal → **Data Centers → New → VMware vCenter**. Add VMs (`name = ip | tag1, tag2` per line) and
   set a username/password. Save.
2. SmartConsole → **New → More → Server → Data Center → VMware vCenter**.
   - **Hostname:** the portal's bare host, e.g. `dcsim.ai.alshawwaf.ca` (no `https://`, no `/path`).
   - **Username / Password:** the credentials you set on the portal DC.
3. **Test Connection**, then **Select objects** — the inventory tree + Tags appear.

> If objects don't refresh, **delete and re-add** the DC object in SmartConsole — it caches a broken
> topology and only does a clean full sync on (re)connect.

## Endpoints served

**SOAP** (`/sdk`, apex; `/vcenter/{token}/sdk` token form kept for debugging):
- `GET /sdk/vimServiceVersions.xml` — API version negotiation (matched to a real vCenter 8.0.3)
- `POST /sdk` — `RetrieveServiceContent`, `Login` (sets the `vmware_soap_session` cookie),
  `CreatePropertyCollector`, `CreateContainerView`, `CreateFilter`, `WaitForUpdates[Ex]`,
  `DestroyPropertyFilter` / `CancelWaitForUpdates` / `DestroyView`, `Logout`, `CurrentTime`

**REST** (`/rest/com/vmware/cis/…`, apex):
- `POST …/session` — basic-auth → `{"value":"<token>"}` (401 on bad creds); `DELETE` = logout
- `GET …/tagging/category` (+ `/id:<id>`), `…/tagging/tag` (+ `/id:<id>`),
  `GET|POST …/tagging/tag-association/id:<id>` — the tag catalog, derived from VMs' tags
- catch-all `…/rest/{path}` → `{"value": []}` so unmodeled calls don't 404-stall

## Object model

You define **VMs** in the portal (`name = ip | tag1, tag2`). The mock synthesizes a realistic
inventory around them and emits it via the PropertyCollector:

```
Datacenters (root folder, group-d1)
└── Datacenter
    ├── vm folder      → VirtualMachine(s)        (name, IP, config.instanceUuid, parent…)
    └── host folder    → Cluster
                         ├── HostSystem ×2         (esxi-01/02.lab.local)
                         └── ResourcePool
```

- **VMs** resolve to their `guest.ipAddress` — usable directly in policy by IP.
- **Tags** (the `| …` list on each VM) become vCenter tags under a single `CloudGuard` category,
  each associated to its member VMs — so policy can target VMs **by tag** (the headline vCenter use
  case: tag a VM in vCenter → it auto-joins the policy group).

## How it works / gotchas (hard-won)

- **PropertyCollector, not RetrieveProperties.** CloudGuard enumerates via
  `CreateContainerView → CreateFilter → WaitForUpdatesEx`. The filter's `propSet` (`all=false`) lists
  the exact properties per type; we return **exactly those**, no extras.
- **Version reset.** CloudGuard persists its WaitForUpdates version per host and reuses it on a fresh
  filter. `WaitForUpdatesEx` returns: full inventory for an empty version; "no changes" for the
  current token; **`InvalidCollectorVersion` fault** for any stale version — which forces the
  controller to reset and re-sync cleanly. `CreateFilter` rotates a per-DC epoch so a reconnect's
  cached version is always stale.
- **Wire encoding matters.** Every requested property is sent as a `<changeSet>` — **even unset ones,
  with no `<val>`** (omitting the root folder's val-less `parent` was a long-standing `fillProperties`
  NPE). `childType` values are **bare** (`Folder`, not `vim.Folder` — the MOB only *displays* the
  `vim.*` form). Array items carry `xsi:type`. The root folder is emitted **last** (children before
  parents).
- Strict CXF: `ServiceContent` + `vimServiceVersions.xml` are matched byte-for-byte to a real vCenter
  8.0.3, or the client reports "connection failed" even on HTTP 200.

## Testing & troubleshooting

- **Portal Activity log** (`/activity`, filter *Data Center*): each `/sdk` row is labeled with its
  SOAP op (`POST /sdk · WaitForUpdatesEx`); `/rest/…` rows show the tagging calls. Request/response
  bodies are captured (password masked).
- **Management side:** `$FWDIR/log/cloud_proxy.elg` (a.k.a. `vsec.elg`) logs the scanner —
  `"Mapping … took N seconds"` and any `fillProperties` errors naming the offending object.
- **Ground-truth tool:** [`tools/capture_vcenter_root.py`](../../tools/capture_vcenter_root.py)
  replays the handshake against a **real** vCenter and prints the raw `objectSet` XML, so the wire
  format can be matched exactly. (The MOB shows property *values*, not the SOAP wire encoding.)

See also the memory note `vcenter-cloudguard-soap-rest` for the full architecture.
