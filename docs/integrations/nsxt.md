# VMware NSX-T (Data Center mock)

Mocks an **NSX-T Manager** in **Policy Mode** (REST) so CloudGuard Controller imports **NS Groups**,
**Virtual Machines**, and **Tags**, with groups resolving to their member VMs.

- Service: [`app/services/nsxt.py`](../../app/services/nsxt.py)
- Router: [`app/routers/nsxt_mock.py`](../../app/routers/nsxt_mock.py)

> **Status:** built and unit-tested; pending first validation against a live CloudGuard. Manager Mode
> is deprecated in R82.10 — this mock targets **Policy Mode** (`/policy/api/v1/…`).

## Configure in SmartConsole

Like vCenter, the NSX-T **Hostname** field is a **bare host**, so the mock is served at the portal
**apex** and resolves the most-recently-created NSX-T DC — **one NSX-T mock per portal**.

1. Portal → **Data Centers → New → NSX-T**. Add VMs and NS Groups; set credentials (NSX-T needs
   **Auditor**-or-higher). Save.
2. SmartConsole → **New → More → Cloud → Data Center → NSX-T**.
   - **Hostname:** the portal's bare host (e.g. `dcsim.ai.alshawwaf.ca`).
   - **Username / Password:** the credentials you set on the portal DC.
3. **Test Connection** → **Select objects**.

## Endpoints served

Apex (`/…`) plus token form (`/nsxt/{token}/…`) for debugging. Auth is HTTP Basic **or** a session
cookie:

- `POST /api/session/create` — form `j_username`/`j_password` → sets `JSESSIONID` + `X-XSRF-TOKEN`
  (403 on bad creds); `POST /api/session/destroy`
- `GET /policy/api/v1/infra/domains` — domains
- `GET /policy/api/v1/infra/domains/default/groups` — NS Groups
- `GET /policy/api/v1/infra/domains/default/groups/{id}/members/virtual-machines` — group members
- `GET /policy/api/v1/infra/domains/default/groups/{id}/members/ip-addresses` — group → member IPs (the call CloudGuard makes to resolve a group)
- `GET /policy/api/v1/infra/realized-state/virtual-machines` — VMs (with tags, no IP)
- `GET /policy/api/v1/infra/realized-state/enforcement-points/default/vifs` — VIFs, **Policy-mode** path (IP ↔ VM via `owner_vm_id`)
- `GET /api/v1/fabric/vifs` — VIFs, Manager-API alias (same data)
- catch-all `GET /policy/api/v1/{path}` and `/api/v1/{path}` → empty `ListResult` (no 404-stall)

Responses use the NSX-T `{"results": […], "result_count": N}` envelope; tags are `{scope, tag}`.

## Object model

- **Virtual Machines** — from realized-state; IPs come from the **VIFs** endpoint (joined by
  `owner_vm_id`), matching how NSX-T separates inventory from fabric.
- **NS Groups** — resolve to their **member VMs** (`…/members/virtual-machines`), so policy can target
  a group and pick up the right IPs.
- **Tags** — `{scope, tag}` pairs on VMs.

## Gotchas

- Apex single-tenant (bare hostname) — same constraint and routing model as
  [vCenter](vcenter.md).
- Per the project rule, **groups must resolve to member VMs** — an empty group object is useless in a
  PoV. Verify member resolution after import.

## Testing

Portal **Activity log** (filter *Data Center*) classifies `/policy/`, `/api/session`, and `/api/v1/`
as Data Center calls and captures bodies (password masked) — so the exact Policy-Mode calls
CloudGuard makes are visible and any unmodeled endpoint can be filled in from the trace.
