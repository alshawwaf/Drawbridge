# Deploying to Dokploy

Hosted on **Dokploy** (panel: https://dokploy.ai.alshawwaf.ca/). Dokploy's Traefik handles the
domain and Let's Encrypt TLS, so the Check Point gateway sees a publicly-trusted HTTPS feed with
no cert-trust step. (Caddy / `docker-compose.yml` are only for standalone local/lab runs.)

## One-time setup

1. **Create an Application** — your project → *Create Service* → *Application*.
2. **Source** — the Git repo for this project (use a Check Point-approved remote per org policy),
   or a Docker image you've pushed to a registry.
3. **Build** — type *Dockerfile*; build context `/`, Dockerfile `Dockerfile`.
4. **Port** — set the app/exposed port to **8000** (uvicorn's listen port).
5. **Domain** — add your domain (e.g. `dcsim.ai.alshawwaf.ca`). Dokploy provisions the
   Let's Encrypt cert via Traefik automatically.
6. **Persistent volume** — add a mount at container path **`/data`**. SQLite lives there;
   without this, all feeds and poll history are wiped on every redeploy.
7. **Environment variables**:
   ```
   DCSIM_BASE_URL=https://<your-domain>          # MUST equal the domain in step 5
   DCSIM_SESSION_SECRET=<openssl rand -base64 32>
   DCSIM_ADMIN_USERNAME=admin
   DCSIM_ADMIN_PASSWORD=<choose a strong password>
   DCSIM_DATABASE_URL=sqlite:////data/dcsim.db
   DCSIM_ENCRYPTION_KEY=<openssl rand -base64 32>   # optional — encrypts saved gateway + DC creds
   DCSIM_SYSLOG_PORT=5514                            # SIEM receiver port (0 disables it)
   ```
8. **Deploy.** Sign in at your domain as the admin user above.

## Extra ports (Nutanix 9440, SIEM receiver 5514)

Two integrations don't ride the standard HTTPS-on-443 path and need their ports published explicitly
on the Dokploy host (skip whichever you won't demo):

- **Nutanix — 9440 (HTTPS).** CloudGuard's Prism connector hardcodes port `9440`, so the portal must
  answer there. Add a Traefik entrypoint for `9440` that routes to the app (same cert/app as 443), or
  run a `socat 9440→443` passthrough on the host. See [docs/integrations/nutanix.md](docs/integrations/nutanix.md).
- **SIEM receiver — 5514 (TCP *and* UDP).** Check Point's Log Exporter sends raw syslog/CEF/LEEF —
  **not** HTTP — so it bypasses Traefik's HTTP routing. Set `DCSIM_SYSLOG_PORT=5514` and publish the
  port straight to the app container: add a TCP **and** a UDP entrypoint for `5514`, or map the host
  port directly. See [docs/integrations/siem.md](docs/integrations/siem.md). Set `DCSIM_SYSLOG_PORT=0`
  to turn the listener off entirely.

## Why each setting matters

- **`DCSIM_BASE_URL`** is what the portal prints as the feed URL you paste into SmartConsole —
  it must match the public domain, or the URLs you hand out will be wrong.
- The container runs uvicorn with `--proxy-headers`, so the **live poll log shows the real
  gateway IP** (from Traefik's `X-Forwarded-For`), not Traefik's address.
- **`DCSIM_ENCRYPTION_KEY`** encrypts saved gateway and datacenter credentials at rest (AES-256-GCM).
  Optional — it falls back to `DCSIM_SESSION_SECRET`; set a dedicated key so rotating the session
  secret doesn't make stored credentials unreadable.
- A Docker `HEALTHCHECK` hits `/healthz`, so Dokploy reports container health.

## Updating

Push to the tracked branch (or hit *Redeploy*). The `/data` volume preserves all feeds and poll
history across deploys.

## Reachability check

The customer's CP Management/Gateway must reach `https://<your-domain>` on 443. From a gateway
shell: `curl -s https://<your-domain>/healthz` should return `{"status":"ok"}`.
