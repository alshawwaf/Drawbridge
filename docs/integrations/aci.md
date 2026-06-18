# Cisco ACI / APIC (Data Center mock)

Mocks a **Cisco APIC** controller (REST) so CloudGuard Controller **R82.10** imports the
**Tenant → Application Profile → EPG**, **ESG**, and the endpoint IPs behind each group — without a
real ACI fabric.

- Service: [`app/services/aci.py`](../../app/services/aci.py)
- Router: [`app/routers/aci_mock.py`](../../app/routers/aci_mock.py)

> **Status:** first cut — built to the R82.10 admin guide + the public APIC REST API, verified
> end-to-end (login, class queries, auth, UI). **Pending the first real-CloudGuard trace** to confirm
> the exact classes CloudGuard queries (every `/api/...` call is in the Activity log; unmodeled
> classes return an empty `imdata` so enumeration never stalls).

## R82.10 contract

Per the [CloudGuard Controller Cisco ACI page](https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_CloudGuard_Controller_AdminGuide/Content/Topics-CGRDG/Supported-Data-Centers-Cisco-ACI.htm):

| Aspect | Value |
|---|---|
| Imports | **Tenant**, **Application Profile**, **EPG**, **ESG**, **L2 Out**, **L2 External EPG** (+ Name Alias) |
| **URLs** field | a **list of full URLs** (scheme required, `https://<ip>`); multiple = APIC cluster members |
| Auth | APIC **username + password** (`POST /api/aaaLogin.json` → token used as the `APIC-cookie`); role: read on Tenant/EPG. Login-domain syntax `apic:<domain>\<user>` |
| API | class queries `GET /api/node/class/<class>.json`; envelope `{"totalCount","imdata":[{class:{attributes,children}}]}` |

## Routing — path-based

The URLs field takes a full URL, so this mock is **path-based** (token in the path) — a portal can
host **many** ACI mocks. The admin pastes `https://<portal>/aci/<token>` into the URLs field; CloudGuard
appends `/api/aaaLogin.json`, `/api/node/class/<class>.json`, etc. (No apex `/api/` route, so no
collision with the NSX-T family's `/api/session` + `/api/v1`.)

## Configure in SmartConsole

1. Portal → **Data Centers → New → Cisco ACI**. Set the Tenant + App Profile, add EPGs / ESGs
   (`Name = ip1, ip2`), and optionally a username/password (blank = open lab).
2. SmartConsole → **New → More → Cloud → Data Center → Cisco ACI…**
   - **URLs:** paste `https://dcsim.ai.alshawwaf.ca/aci/<token>` (shown on the DC page).
   - **Username / Password:** the credentials you set (or anything, open lab).
3. **Test Connection → Select objects.**

## Endpoints served (path-based)

- `POST /aci/<token>/api/aaaLogin.json` — login → token + `APIC-cookie`; `…/aaaRefresh.json` too
- `GET /aci/<token>/api/node/class/<class>.json` (and `/api/class/<class>.json`):
  - `fvTenant` → the Tenant · `fvAp` → the Application Profile
  - `fvAEPg` → EPGs · `fvCEp` → endpoints (one per EPG member IP, `dn` under its EPG, with `ip`/`mac`)
  - `fvESg` → ESGs (each with `fvEPSelector` children carrying the member IPs) · `fvEPSelector` → flat
  - `l2extOut` / `l2extInstP` → empty (not modeled yet)
- catch-all `GET /aci/<token>/api/...` (incl. `/api/mo/<dn>`) → empty `imdata`

## Object model

`uni/tn-<tenant>/ap-<ap>/epg-<name>` for EPGs; each EPG member IP becomes an `fvCEp`
(`…/epg-<name>/cep-<mac>`, MAC synthesized from the IP) so CloudGuard maps the endpoint back to its
EPG by DN prefix. ESGs are `…/ap-<ap>/esg-<name>` with IP-based `fvEPSelector` children, so they
resolve to addresses (and can span EPGs). One Tenant + one Application Profile per mock.

## Auth

`aaaLogin` validates the configured username/password (if set) and returns **401** otherwise; the
issued token is set as the `APIC-cookie` and required on subsequent queries. No creds = open lab.
The password is masked in the Activity log (`aaaLogin` body's `pwd`).

## Diagnostics

[Activity log](/activity?kind=datacenter) → filter **Data Center** shows every `/api/...` class query
(request + response). After a change, **delete + re-add** the object in SmartConsole to force a fresh
sync.
