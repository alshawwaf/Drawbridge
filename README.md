<div align="center">

# 🌉 Drawbridge

### The Check Point integration simulator for PoVs & demos

*Stand up the **external systems Check Point integrates with** — clouds, datacenters, threat-intel feeds, a SIEM — so SEs and partners can demo the whole CloudGuard / dynamic-object surface end-to-end, **without** real infrastructure.*

![Version](https://img.shields.io/badge/version-1.0.0-ff3d9a)
![Validated](https://img.shields.io/badge/validated-R82.10-7b3ff2)
![Tests](https://img.shields.io/badge/tests-251%20passing-34d399)
![Python](https://img.shields.io/badge/python-3.12-3b82f6)
![TLS](https://img.shields.io/badge/TLS-always%20verified-15935a)
![License](https://img.shields.io/badge/license-proprietary-5b6678)

</div>

---

Drawbridge **acts as the systems Check Point talks to**, so you can demo CloudGuard / dynamic-object
integrations during a PoV — **without** a real datacenter, cloud account, threat-intel server, or SIEM.
Same idea as a RADIUS/TACACS simulator: it stands up the *thing being integrated with*, not the Check
Point side.

You author inventory and feeds in the UI; the portal serves them at stable HTTPS URLs in the **exact**
format SmartConsole and the gateway expect. Paste a URL into a Data Center / Generic Data Center / IoC /
Network Feed object, hit **Test Connection**, and watch objects sync live. It also covers the **reverse**
side (a SIEM receiver for Check Point's Log Exporter).

> 💡 The mocks are built to each provider's *exact* API contract and validated against a live **R82.10**
> Management Server — so they connect on the first or second try instead of after weeks of guessing.

> **Policy automation moved out.** The access-automation / dynamic-layers / Management-API side of the old
> monolith now lives in its own product, **PolicyPilot**. Drawbridge is purely the integration simulator —
> feed Drawbridge's data *into* a real Management Server running PolicyPilot.

---

## ✨ What you can simulate

**Feeds & data centers Check Point polls** — define the inventory once; the portal answers in the
provider's own API at a stable URL. Full per-integration docs (what it mocks, how to point Check Point at
it, endpoints, object model, gotchas) live in **[docs/integrations/](docs/integrations/)**.

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

**Beyond polling:**

- 🔁 **[SIEM receiver](docs/integrations/siem.md)** *(reverse)* — point Check Point's **Log Exporter** at
  the portal; it **auto-detects** the format (CEF / LEEF / JSON / key=value / syslog) over TCP+UDP and
  shows the logs arriving live — proof gateway logs reach the SIEM, with no real Splunk/QRadar.

---

## 🎬 Live-demo tooling

- **[Scenarios](docs/integrations/scenarios.md)** — mutate a data center's inventory on cue (flip a tag,
  scale out, blocklist) via single edits or **timed preset runs**; CloudGuard's next ~30s scan re-resolves
  the affected dynamic objects and rules live. Each preset carries an SE **talk-track** (the customer story
  + the exact SmartConsole moves to show), and **baseline / reset** restores the pre-demo state.
- **Seed / Export / Import** — one click **seeds a realistic environment** (feeds + datacenters + a running
  scenario). **Export** the whole environment to a portable JSON bundle to hand a colleague or restore
  per-customer, and **Import** one back. Bundles never carry credentials.
- **Activity log** (`/activity`) — every feed poll, mock API call, and scenario mutation, **live and
  filterable**, with the full (redacted) request and response for troubleshooting + demos.

Everything is multi-tenant (per portal login). Feeds, datacenters, and SIEM logs are all create / edit /
delete with in-place inline editing on detail pages.

---

## 🚀 Quick start (local dev)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DCSIM_ADMIN_PASSWORD='<choose-a-strong-password>'   # else a random one is printed at startup
export DCSIM_SESSION_SECRET=$(openssl rand -base64 32)
uvicorn app.main:app --reload
```

Open <http://localhost:8000>, sign in as `admin`, then open the **Seed an environment** menu on the
dashboard and click **✨ Demo environment** for a ready-made set — or build it by hand:

1. **New Generic DC feed** → add objects (`Name = range1, range2`, one per line).
2. Copy the feed URL it gives you.
3. In SmartConsole: **Objects → New → More → Cloud → Data Center → New Generic Data Center…**, paste the
   URL, set the interval, **Test Connection**.
4. Watch the **Live polls** panel fill in as the gateway fetches.

---

## ☁️ Hosted deployment (Dokploy)

Deploy via **Dokploy** — Traefik handles the domain + Let's Encrypt TLS, so the gateway sees a
publicly-trusted HTTPS feed with no cert-trust step. See **[DEPLOY.md](DEPLOY.md)** for the step-by-step
(build from the `Dockerfile`, expose port 8000, add a domain, mount `/data`, set the `DCSIM_*` env vars).
Two integrations want extra ports published — Nutanix on **9440** (its connector hardcodes that) and the
SIEM receiver on **5514/tcp+udp** — both covered in DEPLOY.md.

### Standalone / local lab (Caddy)

For a self-contained run without Dokploy (e.g. an isolated customer lab):

```bash
cp .env.example .env     # set DCSIM_DOMAIN, DCSIM_BASE_URL, and the secrets
                         # (DCSIM_SESSION_SECRET + DCSIM_ENCRYPTION_KEY: openssl rand -base64 32)
docker compose up -d --build
```

Caddy obtains the cert for `DCSIM_DOMAIN` (use `localhost` for an internal cert). The bundled
`docker-compose.yml` also publishes the Nutanix `9440` and SIEM `5514` ports.

---

## 🔒 Security / org policy

- Portal management endpoints require login; feed endpoints are public-by-design (the gateway must reach
  them) but guarded by a long random token plus an optional per-feed credential.
- TLS 1.2+ via Caddy/Traefik; defensive HTTP response headers (anti-clickjacking, nosniff, HSTS); no
  secrets in code; portal logins use PBKDF2; saved **datacenter credentials are AES-256-GCM encrypted at
  rest** (`DCSIM_ENCRYPTION_KEY`, falls back to the session secret); parameterized queries via SQLAlchemy;
  feed input validated against the Check Point schema.
- **The public base URL is portal-managed** — set it from **Settings** to restamp every emitted feed URL
  with no redeploy (`DCSIM_BASE_URL` is the fallback). See [docs/settings.md](docs/settings.md).
- **PoV bundles carry no credentials** — datacenter auth is stripped on export; re-enter it after import.
- **Use demo/synthetic data only.** Do not upload real customer threat-intel; anything sensitive must stay
  on Check Point-controlled infrastructure.

---

## ✅ Tests

```bash
pip install pytest && pytest -q          # 251 tests, all green
```

---

## 📚 More

- **[docs/getting-started.md](docs/getting-started.md)** — the SE first-PoV walkthrough.
- **[docs/integrations/](docs/integrations/)** — per-integration setup, endpoints, object model, gotchas.
- **[CHANGELOG.md](CHANGELOG.md)** — what's in this release.
