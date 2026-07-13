# Drawbridge

A Datacenter Simulator that serves Check Point / CloudGuard-format datacenter feeds for PoV demos.

Part of the [Dev Hub](https://github.com/alshawwaf/dev-hub) ecosystem — deploy the whole suite with [ubuntu-dokploy-ai](https://github.com/alshawwaf/ubuntu-dokploy-ai).

![Validated](https://img.shields.io/badge/validated-R82.10-7b3ff2)
![Tests](https://img.shields.io/badge/tests-251%20passing-34d399)
![Python](https://img.shields.io/badge/python-3.12-3b82f6)
![License](https://img.shields.io/badge/license-proprietary-5b6678)

## Overview

Drawbridge **acts as the external systems Check Point integrates with** — clouds, datacenters,
threat-intel feeds, and a SIEM — so SEs and partners can demo the full CloudGuard / dynamic-object
surface end-to-end **without** real infrastructure. Same idea as a RADIUS/TACACS simulator: it stands up
the *thing being integrated with*, not the Check Point side.

You author inventory and feeds in the portal UI; Drawbridge serves them at stable HTTPS URLs in the
**exact** format SmartConsole and the gateway expect. Paste a URL into a Data Center / Generic Data
Center / IoC / Network Feed object, hit **Test Connection**, and watch objects sync live. It also covers
the **reverse** direction — a SIEM receiver for Check Point's Log Exporter.

The mocks are built to each provider's exact API contract and validated against a live **R82.10**
Management Server, so they connect on the first or second try instead of after weeks of guessing.

> **Policy automation moved out.** The access-automation / dynamic-layers / Management-API side of the
> earlier monolith now lives in its own product, [PolicyPilot](https://github.com/alshawwaf/PolicyPilot).
> Drawbridge is purely the integration simulator — feed its data *into* a real Management Server running
> PolicyPilot.

## Features

**Feeds and datacenters Check Point polls** — define the inventory once and the portal answers in the
provider's own API at a stable URL. Full per-integration docs (object model, how to point Check Point at
it, endpoints, gotchas) live in [docs/integrations/](docs/integrations/).

| Integration | Mocks | Check Point object |
|---|---|---|
| [Generic Data Center](docs/integrations/generic-datacenter.md) | sk167210 JSON server | Generic Data Center |
| [Network Feed](docs/integrations/network-feed.md) | feed server (flat list / JSON + JQ) | Network Feed |
| [IoC Feed](docs/integrations/ioc-feed.md) | Custom Intelligence — CSV / STIX 1.x / Custom CSV / Snort | Threat Prevention (Anti-Bot / AV / IPS) |
| [OpenStack](docs/integrations/openstack.md) | Keystone + Nova + Neutron | Data Center → OpenStack |
| [VMware vCenter](docs/integrations/vcenter.md) | vSphere SOAP + REST | Data Center → vCenter |
| [VMware NSX-T](docs/integrations/nsxt.md) | NSX-T Policy Mode REST (Local Manager) | Data Center → NSX-T |
| [VMware Global NSX-T](docs/integrations/global-nsxt.md) | NSX-T Global Manager / Federation | Data Center → Global NSX-T |
| [Proxmox VE](docs/integrations/proxmox.md) | Proxmox `/api2/json` REST | Data Center → Proxmox |
| [Cisco ACI](docs/integrations/aci.md) | APIC REST — XML (`aaaLogin` + class queries) | Data Center → Cisco ACI |
| [Kubernetes](docs/integrations/kubernetes.md) | kube-apiserver REST (bearer token) | Data Center → Kubernetes |
| [Nutanix Prism](docs/integrations/nutanix.md) | Prism REST v3 + v4 (Basic auth) | Data Center → Nutanix |

**Reverse — Check Point sends to the portal**

- **[SIEM receiver](docs/integrations/siem.md)** — point Check Point's **Log Exporter** at the portal; it
  auto-detects the format (CEF / LEEF / JSON / key=value / syslog) over TCP+UDP and shows logs arriving
  live, proving gateway logs reach the SIEM with no real Splunk/QRadar.

**Live-demo tooling**

- **[Scenarios](docs/integrations/scenarios.md)** — mutate a datacenter's inventory on cue (flip a tag,
  scale out, blocklist) via single edits or **timed preset runs**; CloudGuard's next scan re-resolves the
  affected dynamic objects and rules live. Each preset carries an SE **talk-track**, and **baseline /
  reset** restores the pre-demo state.
- **Seed / Export / Import** — one click **seeds a realistic environment** (feeds + datacenters + a
  running scenario). **Export** the whole environment to a portable JSON bundle to hand a colleague or
  restore per-customer, and **Import** one back. Bundles never carry credentials.
- **Activity log** (`/activity`) — every feed poll, mock API call, and scenario mutation, **live and
  filterable**, with the full (redacted) request and response for troubleshooting and demos.

Everything is per portal login. Feeds, datacenters, and SIEM logs are all create / edit / delete with
in-place inline editing on detail pages.

## Screenshots

<!-- Add portal screenshots here (dashboard, a datacenter detail page, the live SIEM view). -->

## Quick start (local dev)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DCSIM_ADMIN_PASSWORD='<choose-a-strong-password>'   # else a random one is printed at startup
export DCSIM_SESSION_SECRET=$(openssl rand -base64 32)
uvicorn app.main:app --reload
```

Open <http://localhost:8000>, sign in as `admin`, then use the **Seed an environment** menu on the
dashboard for a ready-made set — or build it by hand:

1. **New Generic DC feed** → add objects (`Name = range1, range2`, one per line).
2. Copy the feed URL it gives you.
3. In SmartConsole: **Objects → New → More → Cloud → Data Center → New Generic Data Center…**, paste the
   URL, set the interval, **Test Connection**.
4. Watch the **Live polls** panel fill in as the gateway fetches.

See [docs/getting-started.md](docs/getting-started.md) for the full first-PoV walkthrough.

## Deployment

Drawbridge deploys automatically via [ubuntu-dokploy-ai](https://github.com/alshawwaf/ubuntu-dokploy-ai)
at **dcsim.\<your-domain\>**. Dokploy clones the repo and builds from the `Dockerfile`; **Traefik**
terminates TLS and routes the domain to the container's HTTP port 8000, so the gateway sees a
publicly-trusted HTTPS feed with no cert-trust step. The Dokploy path uses
[`docker-compose.dokploy.yml`](docker-compose.dokploy.yml) (app service only — no bundled proxy, no host
port publishing).

Two integrations use extra **non-HTTP ports** that are optional and **not** published by default (Traefik
routes only the HTTP port). To use them, add a dedicated Traefik TCP/UDP entrypoint and open the host
firewall:

- **5514/tcp+udp** — SIEM receiver (Check Point Log Exporter target).
- **9440/tcp** — Nutanix Prism (CloudGuard's connector hardcodes port 9440).

### Standalone / local lab (Caddy)

For a self-contained run without Dokploy (e.g. an isolated customer lab), the bundled
[`docker-compose.yml`](docker-compose.yml) fronts the app with **Caddy** for auto-TLS and already
publishes the Nutanix `9440` and SIEM `5514` ports:

```bash
cp .env.example .env     # set DCSIM_DOMAIN, DCSIM_BASE_URL, and the secrets
docker compose up -d --build
```

Caddy obtains the certificate for `DCSIM_DOMAIN` (use `localhost` for an internal cert). See
[DEPLOY.md](DEPLOY.md) for the full step-by-step, including the extra-ports setup.

## Configuration

All environment variables are prefixed `DCSIM_`. The full list with inline notes is in
[.env.example](.env.example); the ones you'll usually set:

| Variable | Default | Purpose |
|---|---|---|
| `DCSIM_BASE_URL` | `http://localhost:8000` | Public URL used to build the feed URLs shown to the SE. Behind a proxy, your HTTPS domain. Also settable at runtime from **Settings**. |
| `DCSIM_DOMAIN` | `localhost` | Domain Caddy obtains a Let's Encrypt certificate for (`docker-compose.yml` only). |
| `DCSIM_SESSION_SECRET` | *(empty)* | Cookie-signing key for portal sessions. **Set in production** (`openssl rand -base64 32`); if empty, an ephemeral key is used and sessions drop on restart. |
| `DCSIM_ENCRYPTION_KEY` | *(falls back to session secret)* | Dedicated AES-256-GCM key for datacenter credentials at rest. Recommended in production so rotating the session secret doesn't orphan stored secrets. |
| `DCSIM_ADMIN_USERNAME` | `admin` | Seed portal admin username. |
| `DCSIM_ADMIN_PASSWORD` | *(empty)* | Seed portal admin password. If blank, a random one is generated and printed to the logs once at first startup. |
| `DCSIM_DATABASE_URL` | `sqlite:///./data/dcsim.db` | SQLite location. The container uses `/data` via a named volume. |
| `DCSIM_SYSLOG_PORT` | `5514` | TCP+UDP port the SIEM / Log Exporter receiver binds. Set `0` to disable the listener. |
| `DCSIM_FRAME_ANCESTORS` | *(auto)* | CSP `frame-ancestors` override. Blank auto-allows `self` plus the parent domain of `DCSIM_BASE_URL` (so a sibling like the Dev Hub can embed the portal). |

## Security

- Portal management endpoints require login; feed endpoints are public-by-design (the gateway must reach
  them) but guarded by a long random token plus an optional per-feed credential.
- TLS 1.2+ via Caddy/Traefik; defensive HTTP response headers (anti-clickjacking, nosniff, HSTS); no
  secrets in code; portal logins use PBKDF2.
- Saved **datacenter credentials are AES-256-GCM encrypted at rest** (`DCSIM_ENCRYPTION_KEY`, falls back
  to the session secret); parameterized queries throughout via SQLAlchemy; feed input validated against
  the Check Point schema.
- **PoV bundles carry no credentials** — datacenter auth is stripped on export; re-enter it after import.
- **Use demo / synthetic data only.** Do not upload real customer threat-intel; anything sensitive must
  stay on Check Point-controlled infrastructure.

## Tech stack

- **API / app** — FastAPI + Uvicorn (Python 3.12), served behind Caddy (standalone) or Traefik (Dokploy).
- **Data** — SQLAlchemy over SQLite (single-file DB on a `/data` volume).
- **UI** — Jinja2 server-rendered templates with HTMX for live partial updates (poll feed, activity log),
  a custom CSS theme (dark/light), no frontend framework.
- **Config / secrets** — pydantic-settings; `cryptography` for AES-256-GCM at-rest encryption; `httpx`
  for outbound calls.
- **Packaging** — reproducible Docker image (pinned dependencies, non-root user, stdlib healthcheck).

## Development

```bash
pip install pytest && pytest -q     # 251 tests
```

Layout: `app/routers/` (HTTP + the per-provider API mocks), `app/services/` (feed rendering, exporters,
scenario runner, SIEM listener, crypto), `app/templates/` (Jinja2 UI), `app/schemas/` (feed payload
validation). Per-integration docs are under [docs/integrations/](docs/integrations/); the
[CHANGELOG.md](CHANGELOG.md) tracks releases.

## License

Proprietary — © Check Point Software Technologies Ltd. Provided for internal use and PoV
evaluation/demonstration by Check Point and its authorized partners. See [LICENSE](LICENSE).
