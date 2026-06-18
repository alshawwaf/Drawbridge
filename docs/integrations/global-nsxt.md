# VMware Global NSX-T (Data Center mock)

Mocks an **NSX-T Global Manager** (Federation) so CloudGuard Controller imports the **global** NS
Groups, VMs, and Tags that span sites — the federated sibling of [NSX-T](nsxt.md).

- Service: [`app/services/nsxt.py`](../../app/services/nsxt.py) (shared with NSX-T)
- Router: [`app/routers/nsxt_mock.py`](../../app/routers/nsxt_mock.py) (`/global-manager/…` routes)

> **Status:** Regions (from the global-infra domains) and NS Groups import against live CloudGuard.
> Making the groups **nest under their Region** required giving each group a `parent_path` pointing
> at its domain (see [Region ↔ NS Group nesting](#region--ns-group-nesting) below) — pending a final
> re-test. Per the
> [R82.10 admin guide](https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_CloudGuard_Controller_AdminGuide/Content/Topics-CGRDG/Supported-Data-Centers-VMware.htm),
> the Global Manager is **NSX-T 4.1 only**; config is unified with NSX-T under the `nsxt.` prefix.

## How it differs from NSX-T

Global NSX-T is NSX-T against the **Global Manager** instead of a Local Manager. Same handshake, same
data model — only the **policy path** changes, plus it adds **Regions**:

| | NSX-T (Local Manager) | Global NSX-T (Global Manager) |
|---|---|---|
| Session | `/api/session/create` | `/api/session/create` *(shared)* |
| Groups | `/policy/api/v1/infra/…` | **`/global-manager/api/v1/global-infra/…`** |
| Group `path` | `/infra/domains/default/groups/<id>` | `/global-infra/domains/default/groups/<id>` |
| Imports (R82.10) | NS Groups, **VMs**, Tags | **Regions**, NS Groups, **VIFs as IP expressions** (optional) — **no VMs** |

## Configure in SmartConsole

Apex single-tenant (bare host), like NSX-T — **one Global NSX-T mock per portal**.

1. Portal → **Data Centers → New → Global NSX-T**. Add VMs + NS Groups; set credentials (Auditor+).
2. SmartConsole → **New → More → Cloud → Data Center → VMware by Broadcom → VMware Global NSX-T…**
   - **Hostname:** the portal's bare host (e.g. `dcsim.ai.alshawwaf.ca`).
   - **Username / Password:** the credentials you set on the portal DC.
3. **Test Connection → Select objects.**

## Endpoints served (apex)

- `POST /api/session/create` / `destroy` — shared with NSX-T; resolves the most-recent NSX-T-family DC
- `GET /global-manager/api/v1/global-infra/domains` — global domains → **Regions** (the `default`
  domain becomes the `default` Region)
- `GET …/global-infra/domains/default/groups` — global NS Groups (each carries `parent_path` →
  its domain, so it nests under the Region)
- `GET …/global-infra/domains/default/groups/{id}/members/ip-addresses` — group → member IPs (the call
  CloudGuard actually makes to resolve a group); `…/members/virtual-machines` is also served
- `GET …/global-infra/realized-state/enforcement-points/default/vifs` — VIFs → IPs (the **IP
  expressions** that back the groups, since Global NSX-T imports VIFs rather than VM objects)
- `GET …/global-infra/realized-state/virtual-machines` — served defensively; R82.10 does **not** list
  VMs among Global NSX-T's imported objects, so CloudGuard may not call it
- catch-all `GET /global-manager/api/v1/{path}` → empty `ListResult` (so `/global-infra/sites` and any
  other GM call don't 404-stall before they're modeled)

Routing note: `/policy/…` resolves the **nsxt** DC and `/global-manager/…` the **globalnsxt** DC, so a
portal can run one of each; the shared `/api/session` + `/api/v1` resolve the most-recently-created of
the family.

## Object model

Identical to [NSX-T](nsxt.md): VMs (`name = ip | scope=tag, …`) and NS Groups
(`GroupName = member_tag | grouptag,…`). Groups resolve to their **member VMs** by tag — global groups
just carry a `/global-infra/…` path.

## Confirmed GM scanner paths (from a real-CloudGuard trace)

The Global Manager scanner calls (captured in the portal Activity log):
- `GET /global-manager/api/v1/global-infra/domains` → CloudGuard renders each global **domain** as a
  **Region** (the `default` domain → the `default` Region you see in the dialog).
- `GET …/global-infra/domains/default/groups` → **NS Groups** (served ✓). In the GM dialog these are
  nested **under the Region**, not a separate top-level list like the Local Manager.
- `GET …/global-infra/domains/default/groups/{id}/members/ip-addresses` → group → member IPs.
- `GET /global-manager/api/v1/global-infra/sites` → the Federation **Locations** probe; we return an
  empty list (fine for a single-site lab — Regions come from the domains, not sites).

## Region ↔ NS Group nesting

The R82.10 guide calls a Region *"A group for security and networking policies. Some regions are
created automatically after you onboard locations in Global Manager."* In practice, for a
single-site lab, **CloudGuard maps the `global-infra` `default` domain to the `default` Region** —
confirmed by a real GM trace where CloudGuard, after fetching the domain, runs an internal
`SearchRepository(rootId: default)` (the `default` is the domain id) looking for that region's
children.

For an NS Group to show up *under* that Region, the group must declare the domain as its parent.
Every real NSX-T policy object carries a **`parent_path`** (verified against the NSX-T policy Group
schema; the Federation tooling even re-parents groups purely by rewriting this path). Our mock
originally omitted it, so the groups were fetched but never associated with the Region. The fix:
each group now returns

```
"path":        "/global-infra/domains/default/groups/<id>",
"parent_path": "/global-infra/domains/default",     ← ties the group to the Region
"relative_path": "<id>"
```

(`app/services/nsxt.py::groups`). The same `parent_path` is added on the Local Manager
(`/infra/domains/default`) — it's correct there too and harmless to NSX-T's flat group list.

## Gotchas / pending

- **Regions = the global-infra domains** (confirmed by trace): each domain → a Region. No separate
  region modeling needed for a single-domain demo. Multi-region would mean multiple domains (or
  modeling Federation Locations under `/global-infra/sites`, which we currently return empty —
  harmless for one site).
- After redeploying this change, **delete + re-add** the Global NSX-T object in SmartConsole so it
  re-syncs (it caches the broken topology where the groups didn't nest).
- Apex single-tenant; same diagnostics as [NSX-T](nsxt.md).
