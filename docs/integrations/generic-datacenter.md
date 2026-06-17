# Generic Data Center (feed)

Serves a **Generic Data Center** JSON document (Security-Management feature, **sk167210**) that
SmartConsole polls. This is the project's hero demo — the universal lever: it represents **any**
inventory as named IP groups, including the **fixed-cloud** providers you can't point at the portal
(AWS, Azure, GCP, Oracle OCI).

- Renderer: [`app/services/render.py`](../../app/services/render.py) (`render_generic_dc`)
- Server: [`app/routers/serve.py`](../../app/routers/serve.py)

## Configure in SmartConsole

1. Portal → **New Generic DC feed** → add objects (`Name = range1, range2` per line) → copy the URL.
2. SmartConsole → **Objects → New → More → Cloud → Data Center → New Generic Data Center…**
   - **URL:** `https://<portal>/gdc/<token>.json`
   - Optional **custom header** for auth (see below).
   - **Interval:** default 60s, **minimum 10s** per sk167210.
3. **Test Connection** → watch the **Live polls** panel on the feed page fill in as the gateway
   fetches.

## Endpoint

`GET /gdc/{token}.json` → the sk167210 document, served `Cache-Control: no-store` so every poll
reflects the latest edit immediately. Each fetch is recorded as a **FeedPoll** (proof the sync is
live). Optional auth: a configured custom header must match (else `401`).

## Schema (sk167210)

```json
{
  "version": "1.0",
  "description": "…",
  "objects": [
    { "name": "web-servers", "id": "<uuid>", "description": "…",
      "ranges": ["10.0.0.11", "10.0.0.0/24", "10.0.1.5-10.0.1.9"] }
  ]
}
```

Mandatory: `version` (only `"1.0"`), `objects`, and per object `name`, `id` (UUID), `ranges`.
`ranges` accepts single IPs, CIDRs, and `a-b` ranges. No tags; max 30k IPs total.

## Object model

In the portal each line is `Name = range1, range2, …`. The renderer emits one object per line with a
**stable UUID** (so the gateway sees consistent ids across polls).

## Why it matters

The fixed-cloud datacenter types (AWS/Azure/GCP/OCI) reach hard-coded cloud endpoints and **cannot**
be pointed at the portal. Represent their inventory with a Generic DC feed instead — same dynamic
object experience in the PoV, no cloud account required.
