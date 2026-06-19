# Plan — Check Point Dynamic-Object Integration Simulator

## Goal
A multi-tenant portal that **is** the external server Check Point polls, so SEs/partners can
configure and demo dynamic-object integrations during PoVs with no real backend server. The
dynamic-object analog of the RADIUS/TACACS simulator.

## Locked decisions
- **Hosting:** cloud-hosted via **Dokploy** (Traefik handles domain + Let's Encrypt TLS; panel
  at https://dokploy.ai.alshawwaf.ca/) **and** Docker-portable (Caddy/compose) for local/
  air-gapped labs. See `DEPLOY.md`.
- **v1 scope:** three file feeds (Generic DC, IoC, Network Feed) **+ one cloud-API mock** — all
  shipped, and since extended well beyond: **8 datacenter mocks**, the **Dynamic Layers** push side,
  a **SIEM receiver**, and PoV **seed / bundle** tooling. See `ASSESSMENT.md` for the current state.
- **Stack:** Python · FastAPI · Pydantic · SQLAlchemy 2.0 · SQLite · Jinja2 + HTMX · Caddy.

## Verified feed formats (from the docs — the foundation)
- **Generic Data Center** (sk167210): JSON `{"version":"1.0","objects":[{"name","id"(UUID),
  "ranges":[...],"description"?}]}`. Mandatory: version, objects, name, id, ranges. Ranges:
  single IP / CIDR / start-end, IPv4 & IPv6. Interval default 60s, **min 10s**. Auth = Custom
  Header (key/value). HTTPS cert must be trusted. Auto-enforced, no policy install. → hero demo.
- **Network Feed**: flat list (delimiter + ignore-prefix) or JSON (parsed via a JQ query).
  Data types Domain / IP / IP+Domain. Default interval 60 **min**. Basic auth.
- **IoC Feed**: CSV "Check Point format", header line prefixed `#`, columns
  `name,value,type,confidence,severity,product,comment`; value+type mandatory; types
  IP/IP Range/Domain/URL/MD5/SHA1/SHA256/Mail-*; confidence/severity ∈ {low,medium,high,critical}.

## Architecture
- **Two endpoint classes:** authenticated management API/UI; public feed-serving endpoints
  (`/gdc/<token>.json`, later `/ioc/<token>.csv`, `/netfeed/<token>`) guarded by random token
  + optional per-feed credential.
- **Killer demo feature:** every gateway poll is recorded (timestamp, source IP, UA) and shown
  live in the UI — on-screen proof the sync is working. Scheduled mutations (M4) make objects
  change in real time.
- Caddy auto-TLS solves reachability + cert-trust for hosted PoVs.

## Milestones
- **M0 Foundation** ✅ — app skeleton, config, SQLite models (User/Feed/FeedPoll), session
  login (PBKDF2), poll logging, Dockerfile + Caddyfile + compose, docs.
- **M1 Generic DC** ✅ — schema + range validator, CRUD API, public JSON endpoint, custom-header
  auth, live-poll UI, unit tests.
- **M2 IoC** ✅ — CSV generator (header `#`, column/enum validation), `/ioc/<token>.csv`; later
  extended with **STIX 1.x**, **Custom CSV**, and **Snort** formats.
- **M3 Network Feed** ✅ — flat-list + JSON/JQ modes, basic auth, `/netfeed/<token>`, JQ query
  surfaced for SmartConsole.
- **M4 Scenario engine** ✅ — live mutations, one-click presets (quarantine / scale-out / blocklist),
  **server-side timed runner** + live timeline + per-preset **talk-tracks**, baseline/reset.
- **M5 Cloud-API mock** ✅ — OpenStack chosen, then extended to **8 datacenter providers** built to
  each connector's exact REST/SOAP/XML surface.
- **M6 Polish** ⏳ — **done:** one-click **seed**, PoV **bundle export/import**, talk-tracks, full
  edit/inline-edit. **Pending:** Check Point **branding/logo**.
- _Beyond the plan:_ **Dynamic Layers** push (`set-dynamic-content`, real + mock gateway), saved
  **Gateways** (AES-GCM creds + trust-on-first-use), and a **SIEM receiver** (Log Exporter sink).

## Notes / prerequisites for the demo
- Generic DC pushes updates over port **18208** (Management → Gateway) — customer-side.
- Generic DC is the live-sync hero (10s). Network Feed's 60-min default is too slow for "watch
  it change" demos — lead with Generic DC.
