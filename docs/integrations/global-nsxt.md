# VMware Global NSX-T (Data Center mock)

Mocks an **NSX-T Global Manager** (Federation) so CloudGuard Controller imports the **global** NS
Groups, VMs, and Tags that span sites — the federated sibling of [NSX-T](nsxt.md).

- Service: [`app/services/nsxt.py`](../../app/services/nsxt.py) (shared with NSX-T)
- Router: [`app/routers/nsxt_mock.py`](../../app/routers/nsxt_mock.py) (`/global-manager/…` routes)

> **Status:** built and unit-tested; pending first validation against a live CloudGuard. Per the
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
- `GET /global-manager/api/v1/global-infra/domains/default/groups` — global NS Groups
- `GET …/global-infra/domains/default/groups/{id}/members/virtual-machines` — group members (by tag)
- `GET /api/v1/fabric/vifs` — VIFs → IPs (shared; on the GM these are the **IP expressions** that back
  the groups, since Global NSX-T imports VIFs rather than VM objects)
- `GET …/global-infra/realized-state/virtual-machines` — served defensively; R82.10 does **not** list
  VMs among Global NSX-T's imported objects, so CloudGuard may not call it
- catch-all `GET /global-manager/api/v1/{path}` → empty `ListResult` (so **Regions** and any other GM
  call don't 404-stall before they're modeled)

Routing note: `/policy/…` resolves the **nsxt** DC and `/global-manager/…` the **globalnsxt** DC, so a
portal can run one of each; the shared `/api/session` + `/api/v1` resolve the most-recently-created of
the family.

## Object model

Identical to [NSX-T](nsxt.md): VMs (`name = ip | scope=tag, …`) and NS Groups
(`GroupName = member_tag | grouptag,…`). Groups resolve to their **member VMs** by tag — global groups
just carry a `/global-infra/…` path.

## Gotchas / pending

- **Regions** are listed first among Global NSX-T's imported types, but the exact GM API path/shape
  isn't documented — they currently return empty via the catch-all and will be modeled from the
  **first real-CloudGuard trace** in the [Activity log](nsxt.md) (the proven iterate-from-the-log
  approach). NS Groups → VMs (the policy-relevant objects) work today.
- Apex single-tenant; same diagnostics as [NSX-T](nsxt.md).
