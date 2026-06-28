# Getting started — your first PoV in 15 minutes

A guided first run of **Drawbridge** for an SE: get it up, seed a realistic environment, and run two demos
end-to-end — a **datacenter → dynamic-object sync**, and a **ticket → Check Point rule** on a real SMS.

> 🎯 Goal: by the end you can show a customer (1) CloudGuard resolving live inventory from a mocked
> datacenter, and (2) a ServiceNow-style ticket becoming the minimal, first-match-safe access rule.

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

On the dashboard, open the **Seed an environment** menu → **✨ Demo environment**. This creates feeds,
datacenters, a gateway, a dynamic layer, and a running scenario — so every page has realistic content.

> Prefer the lab-accurate set? Use **Seed SBT Lab Environment** to mirror the Check Point hands-on training
> lab (mock vCenter / NSX-T at the lab IPs), so import → rule → ping validates against the real lab.

---

## 2. Demo A — datacenter → dynamic object (5 min)

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

## 3. Demo B — ticket → Check Point rule (5 min)

Turn an access request into the minimal correct rule on a **real R82.10 SMS** (least-privilege; the engine
only does what the API account is permitted to).

1. **Settings → add a Management Server** (host, API user, password — encrypted at rest). The portal pins
   its cert on first connect.
2. Open **Access automation**, pick the server + layer.
3. Enter a request — e.g. *allow `10.1.1.50` → the DNS servers over DNS*. Click **Decide** (read-only): the
   engine returns **no-op / widen / create**, the reasoning, and the exact placement (first-match-safe).
4. Review and **Apply** (approval-gated). It supports **every access-rule column** — action (Accept / Drop /
   Reject / Ask / Inform / Apply Layer) plus content, time, install-on, and VPN — and records the change for
   **one-click rollback**.

**Automate it:** the same engine is exposed for agents and ticketing systems —
- **Webhook** (ServiceNow / Jira / any system): `POST /access-automation/webhook` with a `webhook`-scope
  API key.
- **MCP** (n8n / LLM agents): connect at `/mcp` — onboarding + connect-config at **`/mcp-guide`**.
- **REST**: `/dbapi/v1` with an `api`-scope key.

Mint keys in **Settings → API keys** (scoped, revocable, shown once). Agentic **publish** to live policy is
off by default — enable it deliberately in *Settings → MCP / agent*.

---

## 4. Hand it off

- **Export** the whole environment (dashboard → Export) to a portable JSON bundle for a colleague or a
  per-customer save. Bundles never carry credentials — re-enter them after **Import**.
- Point teammates at this repo's **[README](../README.md)** and **[docs/integrations/](integrations/)** for
  per-integration detail.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| SmartConsole "Test Connection" fails | Re-check the URL/credentials; for self-signed, confirm the cert pinned on the gateway/DC Edit page. |
| Datacenter object stuck "initializing" | Delete + re-add the DC object in SmartConsole to force a clean full sync (it caches the prior topology). |
| "Too many login requests" on apply | Expected CP throttle under bursts — session reuse handles it; pace rapid applies if needed (Settings → Management API). |
| `/mcp` returns 503 | No active `mcp`-scope key — generate one on `/mcp-guide`. |
