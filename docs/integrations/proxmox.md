# Proxmox VE (Data Center mock)

Mocks a **Proxmox VE** server (`/api2/json` REST) so CloudGuard Controller **R82.10** imports VMs
(with IPs), the node, and tags — without a real Proxmox cluster.

- Service: [`app/services/proxmox.py`](../../app/services/proxmox.py)
- Router: [`app/routers/proxmox_mock.py`](../../app/routers/proxmox_mock.py)

> **Status:** ✅ validated against live CloudGuard R82.10 — connects and imports the full tree:
> **Cluster → Node (with IP) → VMs (with IPs)** in Select-objects. Two things the first trace taught
> us: SmartConsole needs a **real-format Token ID** (`user@realm!name`) even open-lab, and CloudGuard
> anchors the Node tree on **`/cluster/status`** (see below). **Tags** import is **off by default** in
> CloudGuard's Proxmox scanner (the mock serves them regardless), so the Tags column is empty until
> that's enabled.

## R82.10 contract (from the admin guide)

Per the [CloudGuard Controller for Proxmox page](https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_CloudGuard_Controller_AdminGuide/Content/Topics-CGRDG/Supported-Data-Centers-Proxmox.htm):

| Aspect | Value |
|---|---|
| Imports | **VMs** (+IPs via the qemu-guest-agent), **Nodes** (+IPs), optional **Cluster**, **Tags** (import off by default) |
| Hostname field | bare host **or** `host:port` — port optional, **defaults to 8006** |
| Auth | **API token**: `Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>`; role needs `Sys.Audit`, `VM.Audit`, `VM.Monitor` (e.g. `PVEAuditor`) |
| Requirements | Proxmox VE **8.3+**; qemu-guest-agent on a VM is **mandatory** for its IP to import; a VM that's off / agent-less / only `127.0.0.1` imports without an IP |

## Routing — the `:443` gotcha

Proxmox defaults to **port 8006**, but the portal answers on **443**. The Hostname field accepts a
port, so the admin enters **`<portal-host>:443`** and CloudGuard calls
`https://<host>:443/api2/json/...`, which we serve at the **root** (apex single-tenant — one Proxmox
per portal, most-recently-created wins). Plain `<host>` would hit 8006 and miss the portal.

## Configure in SmartConsole

1. Portal → **Data Centers → New → Proxmox**. Add VMs (`name = ip | tag, tag`), the node name, and
   optionally an API token (Token ID + Secret). Blank secret = open lab (any token accepted).
2. SmartConsole → **New → More → Cloud → Data Center → Proxmox…**
   - **Hostname:** `dcsim.ai.alshawwaf.ca:443` (the `:443` is required).
   - **Token ID / Secret:** the API token you set on the portal DC.
3. **Test Connection → Select objects.**

## Endpoints served (apex)

- `GET /api2/json/version` — version probe
- `GET /api2/json/cluster/resources?type=vm` — VMs (`qemu/<vmid>`, `name`, `node`, `status`, `tags`)
- `GET /api2/json/cluster/resources` — nodes **+** VMs (no filter)
- `GET /api2/json/cluster/status` — cluster quorum **+ the node with its IP** (anchors the Node tree;
  CloudGuard calls this and an empty body leaves the VMs un-parented → empty Select-objects tree)
- `GET /api2/json/nodes` — node list
- `GET /api2/json/nodes/{node}/qemu` — VMs on a node
- `GET /api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces` — **VM IPs** (guest agent)
- `GET /api2/json/nodes/{node}/qemu/{vmid}/config` — VM detail (defensive)
- `GET /api2/json/pools` — empty (pools optional)
- `POST /api2/json/access/ticket` — password/ticket flow (defensive; CloudGuard uses a token)
- catch-all `GET /api2/json/{path}` → `{"data": []}`

Token routes `/proxmox/{token}/api2/json/...` mirror these for direct testing. Every response uses
the Proxmox `{"data": …}` envelope.

## Object model

VMs are authored as `name = ip | tag, tag` (reuses the shared VM parser). Each becomes a QEMU VM with
a synthesized `vmid` (100+), all on one node (default `pve`). **Proxmox tags are flat strings** joined
with `;` (no `scope=value` like NSX-T). IPs are only ever returned by the **agent interface** call —
matching real Proxmox, where an off/agent-less VM has no importable IP.

## Auth

API token via the `PVEAPIToken=<id>=<secret>` Authorization header. If a secret is set on the DC, the
mock validates it and returns **401** on mismatch; the secret is stored only as a one-way hash. No
secret = open lab. The token secret is masked in the Activity log (`Authorization` is a redacted
header).

## Diagnostics

Same as the other DC mocks — the [Activity log](/activity?kind=datacenter) shows every `/api2/json`
call (request + response, token masked). After a change, **delete + re-add** the object in
SmartConsole so it re-syncs.
