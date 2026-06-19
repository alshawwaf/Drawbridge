# Check Point Dynamic-Object Integration Simulator

A portal that **acts as the external systems Check Point integrates with**, so SEs and partners can
demo CloudGuard / dynamic-object integrations end-to-end during a PoV — **without** a real
datacenter, cloud account, threat-intel server, or SIEM. Same idea as a RADIUS/TACACS simulator: it
stands up the *thing being integrated with*, not the Check Point side.

You author inventory and feeds in the UI; the portal serves them at stable HTTPS URLs in the exact
format SmartConsole and the gateway expect. Paste a URL into a Data Center / Generic Data Center /
IoC / Network Feed object, hit **Test Connection**, and watch objects sync live. It also covers the
**push** side (Dynamic Layers via the Gaia API) and the **reverse** side (a SIEM receiver for Log
Exporter) — so a single instance demonstrates the whole CloudGuard integration surface.

The mocks are built to each provider's *exact* API contract and validated against a live **R82.10**
Management Server, so they connect on the first or second try instead of after weeks of guessing.

## What you can simulate

**Feeds & data centers Check Point polls** — define the inventory once; the portal answers in the
provider's own API at a stable URL. Full per-integration docs (what it mocks, how to point Check
Point at it, endpoints, object model, gotchas) live in **[docs/integrations/](docs/integrations/)**.

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

- **[Dynamic Layers](docs/integrations/dynamic-layers.md)** *(push)* — author an Access Control
  rulebase in the portal and apply it to a gateway's Gaia API (`set-dynamic-content`), or to a
  built-in **mock gateway** for a no-hardware demo, complete with async task + change summary.
- **[SIEM receiver](docs/integrations/siem.md)** *(reverse)* — point Check Point's **Log Exporter**
  at the portal; it parses **CEF / LEEF / JSON / syslog** over TCP+UDP and shows the logs arriving
  live — proof that gateway logs reach the SIEM, with no real Splunk/QRadar.

## Live-demo tooling

- **[Scenarios](docs/integrations/scenarios.md)** — mutate a data center's inventory on cue (flip a
  tag, scale out, blocklist) via single edits or **timed preset runs**; CloudGuard's next ~30s scan
  re-resolves the affected dynamic objects and rules live. Each preset carries an SE **talk-track**
  (the customer story + the exact SmartConsole moves to show), and **baseline / reset** restores the
  pre-demo state.
- **Seed / Export / Import** — one click **seeds a realistic environment** (feeds + datacenters + a
  gateway + a dynamic layer + a running scenario). **Export** the whole environment to a portable
  JSON bundle to hand a colleague or restore per-customer, and **Import** one back. Bundles never
  carry credentials.
- **Gateways** — saved connection profiles (host, port, username, optional encrypted password) reused
  across applies and fetches. Self-signed lab gateways are handled by **trust-on-first-use** cert
  pinning — TLS verification stays on, never disabled.
- **Activity log** (`/activity`) — every feed poll, mock API call, scenario mutation, and layer apply,
  **live and filterable**, with the full (redacted) request and response for troubleshooting + demos.

Everything is multi-tenant (per portal login). Feeds, datacenters, dynamic layers, gateways, and
SIEM logs are all create / edit / delete with in-place inline editing on detail pages.

## Quick start (local dev)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DCSIM_ADMIN_PASSWORD=changeme            # else a random one is printed at startup
export DCSIM_SESSION_SECRET=$(openssl rand -base64 32)
uvicorn app.main:app --reload
```

Open <http://localhost:8000>, sign in as `admin`, then either click **✨ Seed demo environment** for
a ready-made set, or:

1. **New Generic DC feed** → add objects (`Name = range1, range2`, one per line).
2. Copy the feed URL it gives you.
3. In SmartConsole: **Objects → New → More → Cloud → Data Center → New Generic Data Center…**, paste
   the URL, set the interval, **Test Connection**.
4. Watch the **Live polls** panel fill in as the gateway fetches.

## Hosted deployment (Dokploy)

Deployed via **Dokploy** — Traefik handles the domain + Let's Encrypt TLS, so the gateway sees a
publicly-trusted HTTPS feed with no cert-trust step. See **[DEPLOY.md](DEPLOY.md)** for the
step-by-step (build from the `Dockerfile`, expose port 8000, add a domain, mount `/data`, set the
`DCSIM_*` env vars). Two integrations want extra ports published — Nutanix on **9440** (its connector
hardcodes that) and the SIEM receiver on **5514/tcp+udp** — both covered in DEPLOY.md.

### Standalone / local lab (Caddy)

For a self-contained run without Dokploy (e.g. an isolated customer lab):

```bash
cp .env.example .env     # set DCSIM_DOMAIN, DCSIM_BASE_URL, secrets
docker compose up -d --build
```

Caddy obtains the cert for `DCSIM_DOMAIN` (use `localhost` for an internal cert). The bundled
`docker-compose.yml` also publishes the Nutanix `9440` and SIEM `5514` ports.

## Security / org policy

- Portal management endpoints require login; feed endpoints are public-by-design (the gateway must
  reach them) but guarded by a long random token plus an optional per-feed credential.
- TLS 1.2+ via Caddy/Traefik; no secrets in code (all via env); portal logins use PBKDF2; saved
  **gateway & datacenter credentials are AES-256-GCM encrypted at rest** (`DCSIM_ENCRYPTION_KEY`,
  falls back to the session secret); parameterized queries via SQLAlchemy; feed input validated
  against the Check Point schema.
- **Gateway TLS is always verified.** Self-signed lab gateways are handled by pinning the
  certificate — trust-on-first-use (auto-pinned on first connect, the default) or a manually
  fetched/pasted cert. Verification is never disabled.
- **PoV bundles carry no credentials** — feed auth, datacenter auth, and gateway passwords are
  stripped on export; re-enter them after import.
- **Use demo/synthetic data only.** Do not upload real customer threat-intel; anything sensitive must
  stay on Check Point-controlled infrastructure.

## Tests

```bash
pip install pytest && pytest -q          # 250+ tests, all green
```

See **[PLAN.md](PLAN.md)** for the design and verified feed formats, and **[ASSESSMENT.md](ASSESSMENT.md)**
for a candid state-of-the-build and roadmap.
