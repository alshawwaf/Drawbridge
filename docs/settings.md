# Settings (portal-configurable behaviour & API keys)

The **Settings** page is where an admin tunes the portal at runtime — no code, no env edit, no
redeploy. In Drawbridge it holds two groups of live-editable behaviour (storage/retention and the
public base URL) plus named API keys.

- Settings router (page + save + key create/revoke): [`app/routers/settings.py`](../app/routers/settings.py)
- Setting definitions + value store (DB-backed `AppState`, ~2s cache): [`app/services/app_settings.py`](../app/services/app_settings.py)
- Named API keys (SHA-256 hashed, scoped, revocable): [`app/services/api_keys.py`](../app/services/api_keys.py)
- Env-var fallbacks (`DCSIM_*`): [`app/config.py`](../app/config.py)

> **Policy automation moved out.** The MCP / webhook / ServiceNow secrets and the SMS session-reuse +
> policy-cache knobs that used to live here belong to the access-automation feature, which is now the
> separate **PolicyPilot** product. Drawbridge is the integration simulator only, so those settings are
> not present here.

## Use it

1. Portal → **Settings** (auth-gated; an unauthenticated request redirects to `/login`).
2. Edit any group, then **Save** — `POST /settings` validates + clamps every value and it takes
   effect immediately (the ~2s value cache is busted). **Restore defaults** (`POST /settings/reset`)
   reverts the settings.
3. To mint an API key, fill name + scope + expiry under **API keys** and Save — the plaintext is
   shown **once**.

## 1. Storage & retention

The two high-volume tables (the Activity log and the built-in SIEM receiver) are bounded so a
long-running demo — a Data Center importing on a schedule, or Log Exporter streaming for days — can't
fill the disk. A background sweep (started in `main.lifespan`) enforces the caps.

- **`activity_max_records`** (5000) — hard cap on the Activity log table; older rows are trimmed with a
  cheap indexed delete. **`activity_max_age_days`** (0 = off) additionally drops entries older than N days.
- **`siem_max_records`** (2000) — hard cap on the SIEM (Log Exporter) table so a flooding gateway can't
  fill the disk. It's a live demo viewer, not a log archive.
- **`retention_sweep_min`** (5) — how often the background pass enforces the caps.
- **`retention_notify`** (on) — post a header-bell notification when a sweep trims records, throttled to
  at most once an hour, so retention is never silent.

## 2. Portal

- **`base_url`** — the public URL this portal is reached at (e.g. `https://dcsim.example.com`), stamped
  into the feed / GDC / Keystone URLs shown to the SE. Set it here to change the displayed URLs with no
  redeploy; leave blank to use `DCSIM_BASE_URL` (or `http://localhost:8000` in dev). One-click **adopt**
  offers the URL the request arrived on (via the reverse proxy's `X-Forwarded-*` headers).

  > The session-cookie `Secure` flag is still decided **at startup** from `DCSIM_BASE_URL`'s scheme, so
  > for HTTPS cookie hardening set the env var too.

## 3. API keys

Named, scoped, revocable bearer tokens. Generated via `POST /settings/api-keys`, **shown once** through
a one-time session reveal (never written to the notification log), then only a **SHA-256 hash** remains —
a DB leak exposes no usable credential. A token looks like `dcsim_<scope>_<random>` (256-bit). Optional
**expiry** (presets 30 / 90 days / 1 year / Never, or an explicit date) stops it authenticating after
that time; the table flags expired / expiring-soon / unused keys. **Revoke**
(`POST /settings/api-keys/{id}/revoke`) deletes the key and it stops authenticating immediately.

The three scopes (`api_keys.SCOPES`) are `mcp`, `webhook`, and `api`. These correspond to the
machine endpoints of the **PolicyPilot** access-automation product; Drawbridge itself exposes no
endpoint that consumes them, so keys minted here are only useful when this deployment also fronts those
PolicyPilot endpoints.

## At-rest encryption

`DCSIM_ENCRYPTION_KEY` (AES-256-GCM, falls back to `DCSIM_SESSION_SECRET`) encrypts **saved datacenter
credentials** so a DC detail page can show the password/token-secret back as a copyable masked field.
Set a dedicated key so rotating the session secret doesn't make stored credentials unreadable. See
[docs/integrations/README.md — Credentials](integrations/README.md#credentials).
