# MCP server — connect Drawbridge to n8n / an LLM agent

Drawbridge exposes its access-automation brain as **MCP tools** an LLM agent (via n8n's *MCP Client Tool*
node, or any MCP client) can call: decide on an access request, correlate a service/app name, list
servers/layers, check Terraform/Ansible coverage, and (gated) apply a change.

The tool **logic** ships in `app/services/mcp_tools.py` and is fully tested. The MCP protocol layer uses
the official **`mcp` Python SDK**, which is **not bundled** (org policy: packages come from Artifactory,
not PyPI). Until it's installed the `/mcp` endpoint is simply absent — the rest of the portal is
unaffected.

## 1. Activate

Install the MCP SDK once (it's mounted automatically when present), then set the token from the portal —
no env edit, no redeploy:

```bash
# one-time: install the MCP SDK from your Check Point Artifactory (NOT plain PyPI)
pip install mcp            # via your Artifactory-configured index, then restart Drawbridge
```

Then in the portal: **Settings → MCP / agent → "MCP bearer token"** → enter a long random secret → Save.
That **enables** `/mcp` immediately (the token is stored encrypted at rest, AES-256-GCM). Rotate or clear
it the same way at any time — the endpoint picks up the change per request, with no restart. The
**MCP for agents** page (`/mcp-guide`) shows live status and a "set a bearer token in Settings" link.

`/mcp` is **mounted whenever the SDK is installed**; while no token is configured it returns **503**
(disabled). A `DCSIM_MCP_TOKEN` env var still works as a **fallback** for headless/automated deploys, but
the portal Setting takes precedence. (Same pattern for the ticketing webhook token and the ServiceNow
write-back credential — all set under **Settings**, all stored encrypted.)

**Self-serve onboarding page:** the portal has a **MCP for agents** page at **`/mcp-guide`** (under
*Layers & Gateways*) — live status pills (SDK installed / endpoint enabled / publish gate), a
connect-config generator with copy-paste snippets for Claude Desktop, Cursor, VS Code and n8n (built from
the live origin + a bearer token you type in), and the full tool catalog. Same idea as
<https://mcp.checkpoint.com/>. Point teammates there instead of hand-writing config.

**Standalone alternative** (own port, e.g. if you don't want it on the portal): 
```bash
DCSIM_MCP_TOKEN=... DCSIM_MCP_PORT=8765 python -m app.mcp_server
```

## 2. Connect n8n

In the **AI Agent** → add an **MCP Client Tool** node:
- **Endpoint / SSE URL:** `https://<drawbridge-host>/mcp` (or `http://<host>:8765` standalone)
- **Transport:** Streamable HTTP (or SSE, depending on your n8n version)
- **Headers:** `Authorization: Bearer <DCSIM_MCP_TOKEN>`

n8n discovers the tools automatically (`tools/list`). The agent can then call them by name.

## 3. Tools

| Tool | Does | Writes? |
|------|------|---------|
| `list_management_servers` | the saved SMS targets (id/name/host) | no |
| `list_access_layers(server_id)` | the policy layers on a server | no |
| `decide_access(server_id, source, destination, layer, service?/port?/application?, …)` | **preview** the decision (no_op/widen/create/review) + reasoning + suggestions | no |
| `correlate_service(server_id, name)` | service/protocol name → real CP object, or candidates | no |
| `correlate_application(server_id, name)` | app/site name → real CP object, or candidates | no |
| `summarize_layer(server_id, layer)` | rule counts, Accept/Drop split, Any-dimension counts, inline layers, cleanup-drop presence | no |
| `analyze_policy(server_id, layer)` | summary + shadowed rules (covered by an earlier broader Accept/Drop) + overly-permissive Accepts | no |
| `coverage_lookup(api, name?, version?)` | object/field support across API / Terraform / Ansible | no |
| `apply_access(server_id, …, publish)` | `publish=false` **dry-run** (validate + discard); `publish=true` **commit** | gated |

`summarize_layer` / `analyze_policy` are read-only and **provably conservative** — `analyze_policy` only
flags a rule as shadowed when it can prove an earlier rule fully covers it under first-match (it abstains
on application-layer / opaque cells rather than guessing), and only flags Accepts that are `Any` on a
whole dimension. Good for an agent to *understand* a policy before proposing a change.

## 4. Safety model

- **Auth:** every call requires `Authorization: Bearer <token>` (constant-time checked). The token is set
  in **Settings → MCP / agent** (encrypted at rest), with `DCSIM_MCP_TOKEN` as fallback. No token
  configured → **503** (disabled); wrong/missing token on a configured endpoint → **401**. A DB read
  failure on the token fails **closed** (the endpoint stays disabled), never open.
- **No accidental writes:** `decide_access` is read-only; `apply_access` with `publish=false` rehearses
  the change in a session and **discards** it (nothing committed).
- **Publish is opt-in:** `apply_access(publish=true)` only commits when an admin enables **Settings →
  MCP / agent → "Let the MCP agent publish to live policy"** (`mcp_allow_publish`, default OFF).
  Otherwise it's refused with a message telling the agent to dry-run instead. So an LLM cannot reach live
  policy unless you deliberately allow it.
- The engine's own guarantees still apply end-to-end: an unknown/ambiguous service name returns
  `review` + `suggestions` and **never** produces a wrong call to the SMS.

## 5. Example agent loop

> "Allow 10.1.1.222 to reach the DNS servers over DNS."

1. `correlate_service(server_id, "dns")` → confirms the CP service object.
2. `decide_access(server_id, "10.1.1.222", "<dns group>", "Network", service="domain-udp")` → e.g.
   `widen` with the target rule + reasoning.
3. (if approved) `apply_access(..., publish=false)` to dry-run, then `publish=true` once the admin toggle
   is on.

## 6. Status — validated live

Validated end-to-end against `mcp` SDK 1.28.0 (Streamable-HTTP): a request with no / wrong bearer → 401;
`initialize` → 200 (serverInfo "Drawbridge"); `tools/list` → all 9 tools; `tools/call coverage_lookup`
returns real data; `decide_access` with a bad server id returns its error inside the tool result (no
crash). The endpoint serves at **`/mcp`** (a bare `/mcp` 307-redirects to `/mcp/`; MCP clients, incl.
n8n, follow it preserving the POST). The mounted app's session-manager lifespan is run from the portal's
own lifespan (so you won't see "Task group is not initialized"). The SDK is declared in
`requirements.txt` (install resolves from Artifactory).
