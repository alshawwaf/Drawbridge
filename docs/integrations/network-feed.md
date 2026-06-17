# Network Feed

Serves a **Network Feed** the gateway polls to build a dynamic network object — a flat list of
IPs/ranges, or a JSON document plus a **JQ** query to extract them. Protected with **HTTP Basic**
auth.

- Renderer: [`app/services/render.py`](../../app/services/render.py)
- Server: [`app/routers/serve.py`](../../app/routers/serve.py)

## Configure in SmartConsole

1. Portal → **New Network Feed** → choose the format (flat list, or free-form JSON + a JQ query) →
   set a username/password → copy the URL.
2. SmartConsole → create a **Network Feed** object.
   - **URL:** `https://<portal>/netfeed/<token>`
   - **Authentication:** HTTP Basic — the username/password you set on the portal feed.
3. **Test Connection** → the gateway fetches on its interval; each poll is recorded.

## Endpoint

`GET /netfeed/{token}` → the rendered feed, `Cache-Control: no-store`. HTTP Basic auth: a missing or
wrong credential returns `401 WWW-Authenticate: Basic realm="network-feed"`. Each fetch is recorded
as a **FeedPoll**.

## Formats

- **Flat list** — one IP / CIDR / range per line; emitted verbatim.
- **JSON + JQ** — store any JSON body and a JQ query; the query's output is the feed the gateway
  receives. The body is free-form (not forced into an `{entries}` wrapper), so you can mirror a real
  upstream's shape and extract with JQ.

## Notes

The portal-level endpoint is intentionally unauthenticated (the gateway must reach it) — security is
the unguessable token **plus** the optional Basic credential. Watch the **Live polls** panel on the
feed page to prove the sync.
