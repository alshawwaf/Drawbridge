# VMware Global NSX-T (Data Center mock)

Mocks an **NSX-T Global Manager** (Federation) so CloudGuard Controller imports the **global** NS
Groups, VMs, and Tags that span sites — the federated sibling of [NSX-T](nsxt.md).

- Service: [`app/services/nsxt.py`](../../app/services/nsxt.py) (shared with NSX-T)
- Router: [`app/routers/nsxt_mock.py`](../../app/routers/nsxt_mock.py) (`/global-manager/…` routes)

> **Status:** Connects against live CloudGuard, imports the **Region** (`default`, navigable), and
> resolves both NS Groups' member IPs (all `200`s in the trace). **Known limitation (parked — confirmed
> a CloudGuard behavior, not a mock bug):** the NS Groups do **not** appear under the Region (the
> `default` Region renders empty). This was settled by **decompiling `NsxTScanner` from the R82.10
> hotfix `cms.jar`** (see [Why the groups don't nest](#why-the-groups-dont-nest-decompiled) and the
> [decompile technique](../../README.md)) — the earlier `parent_path` / `origin_site_id` /
> `/global-infra/sites` attempts were chasing fields CloudGuard's model **never reads**. The PoV demos
> NS-Group import via the working [NSX-T (Local Manager)](nsxt.md) object instead. Per the
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
   - **Hostname:** the portal's bare host (e.g. `dcsim.example.com`).
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
- `GET /global-manager/api/v1/global-infra/sites` — the Federation **Location** (one `Site`). **Must
  not be empty** — it's what backs the Region so the groups nest (see below)
- `GET …/global-infra/realized-state/enforcement-points/default/vifs` — VIFs → IPs (the **IP
  expressions** that back the groups, since Global NSX-T imports VIFs rather than VM objects)
- `GET …/global-infra/realized-state/virtual-machines` — served defensively; R82.10 does **not** list
  VMs among Global NSX-T's imported objects, so CloudGuard may not call it
- catch-all `GET /global-manager/api/v1/{path}` → empty `ListResult` (so any GM call we haven't
  modeled returns a valid empty list instead of 404-stalling)

Routing note: `/policy/…` resolves the **nsxt** DC and `/global-manager/…` the **globalnsxt** DC, so a
portal can run one of each; the shared `/api/session` + `/api/v1` resolve the most-recently-created of
the family.

## Object model

Identical to [NSX-T](nsxt.md): VMs (`name = ip | scope=tag, …`) and NS Groups
(`GroupName = member_tag | grouptag,…`). Groups resolve to their **member VMs** by tag — global groups
just carry a `/global-infra/…` path.

## Confirmed GM scanner contract (from a full real-CloudGuard trace)

The Global Manager scan cycle is **exactly four calls** (captured in the portal Activity log) — no
`/regions`, no `/span`, no `…/domain-deployment-maps`:
- `GET /global-manager/api/v1/global-infra/domains` → the `default` domain.
- `GET …/global-infra/domains/default/groups` → the **NS Groups**.
- `GET …/global-infra/domains/default/groups/{id}/members/ip-addresses` → group → member IPs.
- `GET /global-manager/api/v1/global-infra/sites` (called twice) → the Federation **Locations**.

CloudGuard builds the entire Region tree from just those three response bodies (domains, groups,
sites). It never asks for span or deployment-maps, so any cross-object association must be **inferred
from the data in those responses**.

## Why the groups don't nest (decompiled)

Settled by reading CloudGuard's own `NsxTScanner` (R82.10 hotfix `cms.jar`,
`com/checkpoint/datacenter/scanner/nsxt/`) instead of guessing. Three facts decide it:

1. **The `NSGroup` model only deserializes `{id, display_name, description, unique_id, tags}`.** It
   does **not** read `path`, `parent_path`, `span`, or `origin_site_id`. So every nesting field we
   added before was **silently ignored** — they could never have worked. (`Domain` = `{id,
   display_name}`; `Site` = `{id, display_name}`.)
2. **Region = Domain.** `updateRegions` creates one Region per domain (Region uid = the domain's
   `id`, i.e. `"default"`). The NS-group's parent comes from `DcScannerUtils.prepareUpdate`'s **arg #5
   (`setParent`)**, and that value is the **`domainId` passed into `updateNSGroups`**.
3. **`innerRun` runs the group pass twice.** `updateRegions` calls `updateNSGroups(set, Domain.id, …)`
   (parent = the Region) — *but then* `innerRun` runs an **unconditional `updateNSGroups(set, Y, null)`
   with parent = `Y` (the scanner root)**. Both pull the same `/global-infra/domains/default/groups`
   (the second from CloudGuard's checksum cache — which is why the live trace shows only **one** HTTP
   group fetch). CloudGuard's own placement logic decides where the objects land, and live the
   `default` Region renders **empty**.

**The mock cannot override this** — placement happens in the scanner's Java *after* it parses our
(correct, `200`) responses. There is no response shape that makes `/global-infra/domains/default/groups`
return groups to the per-domain pass but nothing to the root pass; it's the same endpoint. So this is a
**CloudGuard-side behavior for a single-domain Global Manager, not a simulator gap** — parked with the
evidence in hand rather than chasing it further.

The dead `parent_path` / `origin_site_id` on `groups()` and the `sites()` endpoint are retained for now
(harmless — ignored by the model) and can be stripped. To revisit only with a **real multi-domain
NSX-T 4.1 GM** capture, where each domain's span might change the placement.

## Gotchas / pending

- **`/global-infra/sites` must return a Location.** An empty list renders the Region as an empty
  placeholder (the domain has no span → its groups realize nowhere). This was the actual cause of
  "Region shows, but no NS Groups under it" — `parent_path` alone didn't fix it.
- **Single Location only.** We return one `Site` (`default`); everything spans it implicitly, so no
  `/span` or `/domain-deployment-maps` is needed. Multi-region would mean multiple Sites + per-group
  span — not modeled (not needed for a single-site PoV).
- **NS Groups don't nest under the Region (parked).** See the box above — the integration connects,
  imports the Region, and resolves group IPs, but the visual nesting is unsolved without a real-GM
  capture. Demo NS Groups via the [NSX-T (LM)](nsxt.md) object.
- **Transient Test Connection 403 (deferred).** `cloud_proxy.elg` showed `getAllDomainsGlobal` failing
  5× with 403 during `connectionMode TestConnection`, then a clean `StandardConnection` scan. Likely
  the GM `/global-infra/domains` call landing before the session cookie is honored during Test
  Connection. The background scan works; revisit only if Test Connection shows red in a demo.
- After a change, **delete + re-add** the object in SmartConsole so it re-syncs (it caches topology).
- Apex single-tenant; same diagnostics as [NSX-T](nsxt.md).
