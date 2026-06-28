# Cisco ACI / APIC (Data Center mock)

Mocks a **Cisco APIC** controller (REST) so CloudGuard Controller **R82.10** imports the
**Tenant → Application Profile → EPG**, **ESG**, and the endpoint IPs behind each group — without a
real ACI fabric.

- Service: [`app/services/aci.py`](../../app/services/aci.py)
- Router: [`app/routers/aci_mock.py`](../../app/routers/aci_mock.py)

> **Status:** the first real trace taught us **CloudGuard's APIC client is XML-only** — it
> JAXB-unmarshals every response, so the JSON first cut failed with `InvalidServerException … Content
> is not allowed in prolog`. The mock now answers **APIC XML for every extension**
> (`.xml`, `.json`, or none — CloudGuard's client never wants JSON), e.g.
> `<imdata totalCount="1"><fvTenant dn="uni/tn-DCSIM" name="DCSIM"/></imdata>`. **Pending re-test** of
> Test Connection. (Every `/api/...` call is in the Activity log; unmodeled classes return an empty
> `imdata` so enumeration never stalls.)

## R82.10 contract

Per the [CloudGuard Controller Cisco ACI page](https://sc1.checkpoint.com/documents/R82.10/WebAdminGuides/EN/CP_R82.10_CloudGuard_Controller_AdminGuide/Content/Topics-CGRDG/Supported-Data-Centers-Cisco-ACI.htm):

| Aspect | Value |
|---|---|
| Imports | **Tenant**, **Application Profile**, **EPG**, **ESG**, **L2 Out**, **L2 External EPG** (+ Name Alias) |
| **URLs** field | a **list of full URLs** (scheme required, `https://<ip>`); multiple = APIC cluster members |
| Auth | APIC **username + password** (`POST /api/aaaLogin.json` → token used as the `APIC-cookie`); role: read on Tenant/EPG. Login-domain syntax `apic:<domain>\<user>` |
| API | class queries `GET /api/node/class/<class>.json`; envelope `{"totalCount","imdata":[{class:{attributes,children}}]}` |

## Routing — apex (host only)

Although the URLs field takes a full URL, **CloudGuard's APIC client uses only the host** and discards
any path (confirmed from a trace: a `/aci/<token>/...` path-based mock 404'd, and the controller
XML-parsed the 404 JSON → "Content is not allowed in prolog"). So the admin enters the **bare host**
and the mock is served at the **apex** — resolving the most-recently created ACI datacenter (**one ACI
per portal**, like vCenter/NSX-T). ACI's `/api/aaaLogin`, `/api/node|class|mo` don't collide with the
NSX-T family's `/api/session` + `/api/v1`. Token routes (`/aci/<token>/api/...`) are kept for testing.

## Configure in SmartConsole

1. Portal → **Data Centers → New → Cisco ACI**. Set the Tenant + App Profile, add EPGs / ESGs
   (`Name = ip1, ip2`), and optionally a username/password (blank = open lab).
2. SmartConsole → **New → More → Cloud → Data Center → Cisco ACI…**
   - **URLs:** the **bare host** `https://dcsim.example.com` (shown on the DC page) — CloudGuard
     ignores any path, so a `/aci/<token>` URL also works but resolves to the same apex.
   - **Username / Password:** the credentials you set (or anything, open lab).
3. **Test Connection → Select objects.**

## Endpoints served (apex; token routes mirror them)

- `POST /api/aaaLogin[.xml|.json]` — login → token + `APIC-cookie`; `/api/aaaRefresh` too
- `GET /api/node/class/<class>[.xml]` (and `/api/class/<class>`):
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
