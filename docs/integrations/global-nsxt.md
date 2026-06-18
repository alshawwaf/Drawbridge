# VMware Global NSX-T (Data Center mock)

Mocks an **NSX-T Global Manager** (Federation) so CloudGuard Controller imports the **global** NS
Groups, VMs, and Tags that span sites — the federated sibling of [NSX-T](nsxt.md).

- Service: [`app/services/nsxt.py`](../../app/services/nsxt.py) (shared with NSX-T)
- Router: [`app/routers/nsxt_mock.py`](../../app/routers/nsxt_mock.py) (`/global-manager/…` routes)

> **Status:** Regions (from the global-infra domains) and NS Groups import against live CloudGuard.
> Making the groups **nest under their Region** required two things, both confirmed from a full GM
> trace: a `parent_path` on each group **and** a real Federation Location at `/global-infra/sites`
> (see [Region ↔ NS Group nesting](#region--ns-group-nesting-what-actually-makes-them-appear)) —
> pending a final re-test. Per the
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

## Region ↔ NS Group nesting (what actually makes them appear)

The R82.10 guide: *"A Region … some regions are created automatically after you onboard locations in
Global Manager."* That `locations` clause is the key. Two things are needed, and both came from the
trace, not a guess:

1. **`parent_path` on each group** → `/global-infra/domains/default` (`app/services/nsxt.py::groups`).
   A real NSX-T policy object always has it; the Federation tooling re-parents groups purely by
   rewriting this path. Necessary, but on its own the groups were still fetched-but-not-nested.
2. **A real Location at `/global-infra/sites`** (`app/services/nsxt.py::sites`). The `default` Region
   renders from the domain, but a global domain's objects only surface where the domain has **span**,
   and span comes from onboarded Locations. With `/sites` empty the domain spanned nothing, so its
   groups realized nowhere. We return **one** `Site` (`site_type: ONPREM_LM`,
   `path: /global-infra/sites/default`); a single Location means everything spans it implicitly,
   which is why CloudGuard needs no `/span` call.

```
GET /global-infra/sites  →  [ { "resource_type": "Site", "id": "default",
                                 "path": "/global-infra/sites/default", "site_type": "ONPREM_LM", … } ]
```

The `parent_path` is also added on the Local Manager (`/infra/domains/default`) — correct there and
harmless to NSX-T's flat group list. The LM has no `/sites` (no Federation Locations).

## Gotchas / pending

- **`/global-infra/sites` must return a Location.** An empty list renders the Region as an empty
  placeholder (the domain has no span → its groups realize nowhere). This was the actual cause of
  "Region shows, but no NS Groups under it" — `parent_path` alone didn't fix it.
- **Single Location only.** We return one `Site` (`default`); everything spans it implicitly, so no
  `/span` or `/domain-deployment-maps` is needed. Multi-region would mean multiple Sites + per-group
  span — not modeled (not needed for a single-site PoV).
- After redeploying this change, **delete + re-add** the Global NSX-T object in SmartConsole so it
  re-syncs (it caches the previous topology where the groups didn't nest).
- Apex single-tenant; same diagnostics as [NSX-T](nsxt.md).
