# Check Point Dynamic-Object Integration Simulator

A portal that **acts as the external server Check Point polls**, so SEs and partners can
demo dynamic-object integrations end-to-end during a PoV — **without** a real datacenter,
cloud account, or threat-intelligence server. Same idea as a RADIUS/TACACS simulator: we
stand up the *thing being integrated with*, not the Check Point side.

You define objects/feeds in the UI; the portal serves them at stable HTTPS URLs in the exact
format SmartConsole and the gateway expect. Paste the URL into a Generic Data Center / IoC /
Network Feed object, hit **Test Connection**, and watch objects sync live.

It also supports **Dynamic Layers** (R82.10 `set-dynamic-content`, a *push* model): author an
Access Control rulebase in the portal and apply it to a gateway's Gaia API — or to a built-in
**mock gateway** for a no-hardware demo, complete with async task + change-summary.

## Status

| Milestone | Scope | State |
|---|---|---|
| M0 | Foundation (app, config, DB, portal auth, Docker/Caddy) | ✅ done |
| M1 | **Generic Data Center** feed end-to-end (the hero demo, 10s sync) | ✅ done |
| M2 | **IoC feed** (Custom Intelligence, native Check Point CSV) — Anti-Bot / AV threat intel | ✅ done |
| M3 | Network Feed (flat list + JSON/JQ, HTTP Basic auth) | ✅ done |
| M4 | **Scenarios** — live inventory mutation (tag flip / scale-out / remove) + named presets + server-side timed runner with live timeline + baseline/reset | ✅ done |
| DC | **Data Centers** — mock OpenStack (Keystone + Nova + Neutron) CP connects to; template for more providers | ✅ done |
| M6 | Branded UI, templates/presets, import/export | ⏳ |
| DL | **Dynamic Layer** (set-dynamic-content): builder, mock Gaia API + real-gateway push, live progress + HTTP trace | ✅ done |
| Logs | App-wide **Activity log** (`/activity`): feed polls, mock Gaia calls, applies — live, filterable, full request/response (redacted) | ✅ done |

See [PLAN.md](PLAN.md) for the full design and the verified feed formats.

## Integrations

Each integration makes the portal *act as the external system Check Point integrates with*. Full
docs — what it mocks, how to point Check Point at it, endpoints, object model, gotchas — live in
**[docs/integrations/](docs/integrations/)**:

| Integration | Mocks | Check Point object |
|---|---|---|
| [Generic Data Center](docs/integrations/generic-datacenter.md) | sk167210 JSON server | Generic Data Center |
| [Network Feed](docs/integrations/network-feed.md) | feed server (list / JSON+JQ) | Network Feed |
| [IoC Feed](docs/integrations/ioc-feed.md) | Custom Intelligence CSV (Check Point format) | Threat Prevention (Anti-Bot / AV) |
| [OpenStack](docs/integrations/openstack.md) | Keystone + Nova + Neutron | Data Center → OpenStack |
| [VMware vCenter](docs/integrations/vcenter.md) | vSphere SOAP + REST | Data Center → vCenter |
| [VMware NSX-T](docs/integrations/nsxt.md) | NSX-T Policy Mode REST (Local Manager) | Data Center → NSX-T |
| [VMware Global NSX-T](docs/integrations/global-nsxt.md) | NSX-T Global Manager / Federation | Data Center → Global NSX-T |
| [Dynamic Layers](docs/integrations/dynamic-layers.md) | Gaia API push (`set-dynamic-content`) | *(push to gateway / mock)* |
| [Scenarios](docs/integrations/scenarios.md) | live inventory mutation + timed presets | *(drives any DC mock's next poll)* |

## Quick start (local dev)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DCSIM_ADMIN_PASSWORD=changeme        # else a random one is printed at startup
export DCSIM_SESSION_SECRET=$(openssl rand -base64 32)
uvicorn app.main:app --reload
```

Open http://localhost:8000 and sign in as `admin`.

1. **New Generic DC feed** → add objects (`Name = range1, range2`, one per line).
2. Copy the feed URL it gives you.
3. In SmartConsole: **Objects → New → More → Cloud → Data Center → New Generic Data Center…**,
   paste the URL, set the interval, **Test Connection**.
4. Watch the **Live polls** panel on the feed page fill in as the gateway fetches.

## Hosted deployment (Dokploy)

Deployed via **Dokploy** — Traefik handles the domain + Let's Encrypt TLS, so the gateway sees a
publicly-trusted HTTPS feed with no cert-trust step. See **[DEPLOY.md](DEPLOY.md)** for the
step-by-step. In short: create a Dokploy *Application*, build from the `Dockerfile`, expose port
8000, add a domain, mount a persistent volume at `/data`, and set the `DCSIM_*` env vars.

### Standalone / local lab (Caddy)

For a self-contained run without Dokploy (e.g. an isolated customer lab):

```bash
cp .env.example .env     # set DCSIM_DOMAIN, DCSIM_BASE_URL, secrets
docker compose up -d --build
```

Caddy obtains the cert for `DCSIM_DOMAIN` (use `localhost` for an internal cert).

## Security / org policy

- Portal management endpoints require login; feed endpoints are public-by-design (the gateway
  must reach them) but guarded by a long random token plus an optional per-feed credential.
- TLS 1.2+ via Caddy; no secrets in code (all via env); PBKDF2 password hashing; parameterized
  queries via SQLAlchemy; feed input validated against the CP schema.
- **Use demo/synthetic data only.** Do not upload real customer threat-intel; if anything
  sensitive is ever involved it must stay on Check Point-controlled infrastructure.

## Tests

```bash
pip install pytest && pytest -q
```
