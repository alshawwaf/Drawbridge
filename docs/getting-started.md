# Getting started — your first PoV in 10 minutes

A guided first run of **Drawbridge** for an SE: get it up, seed a realistic environment, and run the
headline demo end-to-end — a **datacenter → dynamic-object sync** that CloudGuard resolves live.

> 🎯 Goal: by the end you can show a customer CloudGuard resolving live inventory from a mocked
> datacenter, and policy following that inventory as it changes — with no real backend.

> **Policy automation lives elsewhere.** Turning a ticket into a Check Point rule (Access Automation),
> Dynamic Layers, and Management-API / Gaia export moved to the separate **PolicyPilot** product. Point
> PolicyPilot at a real SMS and feed it Drawbridge's simulated data.

---

## 0. Run it (2 min)

**Local (laptop demo):**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
export DCSIM_ADMIN_PASSWORD='<choose-a-strong-password>'
export DCSIM_SESSION_SECRET=$(openssl rand -base64 32)
uvicorn app.main:app --reload
```
Open <http://localhost:8000> and sign in as `admin`.

**Hosted (customer-reachable):** see [DEPLOY.md](../DEPLOY.md) — Dokploy/Traefik gives a publicly-trusted
HTTPS URL so the gateway needs no cert-trust step.

---

## 1. Seed a demo environment (1 min)

On the dashboard, open the **Seed an environment** menu → **✨ Demo environment**. This creates a set of
feeds and datacenters and auto-starts a gentle live scenario — so every page has realistic content.

> Prefer the lab-accurate set? Use **SBT Lab Environment** to mirror the Check Point hands-on training
> lab (mock vCenter / NSX-T at the lab IPs, plus threat feeds), so import → rule → ping validates against
> the real lab.

---

## 2. Demo — datacenter → dynamic object (5 min)

The headline CloudGuard story: inventory in an external system becomes Check Point objects that rules
follow automatically.

1. **Pick a datacenter** (e.g. **vCenter** under *Data Centers*) and copy its endpoint URL from the detail
   page.
2. In **SmartConsole**: *Objects → New → More → Cloud → Data Center* → choose the matching type, paste the
   URL + credentials, **Test Connection**. (For a self-signed lab box, Drawbridge pins the cert — TLS stays
   verified.)
3. Create a **dynamic object** scoped by a tag/folder, drop it into a rule, and install policy.
4. In Drawbridge, open **Scenarios** on that datacenter and run a preset (e.g. *scale out* or *flip a tag*).
   Each preset shows an SE **talk-track** — the customer story + the exact SmartConsole moves to narrate.
5. Within ~30s CloudGuard's next scan re-resolves the object; the rule now covers the changed inventory —
   live, no policy edit. Hit **baseline / reset** to restore the pre-demo state.

Watch every poll in the **Activity log** (`/activity`) — full request/response, redacted, filterable.

---

## 3. Show the reverse side — SIEM receiver (optional)

Point Check Point's **Log Exporter** at the portal on `udp+tcp://<portal-host>:5514`; the built-in sink
auto-detects CEF / LEEF / JSON / syslog and shows logs arriving live at `/siem` — proof gateway logs
reach a SIEM, with no real Splunk/QRadar. Setup + the port-publishing gotchas are in
[docs/integrations/siem.md](integrations/siem.md).

---

## 4. Hand it off

- **Export** the whole environment (dashboard → Export) to a portable JSON bundle for a colleague or a
  per-customer save. Bundles carry feeds + datacenters and **never carry credentials** — re-enter them
  after **Import**.
- Point teammates at this repo's **[README](../README.md)** and **[docs/integrations/](integrations/)** for
  per-integration detail.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| SmartConsole "Test Connection" fails | Re-check the URL/credentials; for self-signed, confirm the cert pinned on the DC Edit page. |
| Datacenter object stuck "initializing" | Delete + re-add the DC object in SmartConsole to force a clean full sync (it caches the prior topology). |
| SIEM receiver stays empty | Packets reach the host but nothing shows → work the NIC → firewall → host socket → container ladder in [siem.md](integrations/siem.md#troubleshooting--packets-reach-the-host-but-nothing-shows-on-siem). |
