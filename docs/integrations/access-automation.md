# Ticket-driven Access Automation

Turn an access request — *let `src` reach `dst` on `service`* — into the **minimal correct change** on a
Check Point access layer, over the Management `web_api`. The engine reads the live rulebase and computes
one of four outcomes: **no-op** (already allowed), **widen** an existing rule, **create** a new
least-privilege rule placed correctly, or **REVIEW** when it can't safely decide. For a PoV this is the
"ServiceNow ticket → firewall rule, with no fat-fingering and no over-grant" story — the FireMon /
Tufin / AlgoSec demo, driven straight off the customer's own policy.

- UI + JSON + webhook router: [`app/routers/access_automation.py`](../../app/routers/access_automation.py)
- The pure decision engine (`decide()`) + apply I/O: [`app/services/access_automation.py`](../../app/services/access_automation.py)
- Ticket payload parsing + result write-back: [`app/services/ticketing.py`](../../app/services/ticketing.py)
- Decision-tree diagram export (single source of truth): [`app/services/decision_tree.py`](../../app/services/decision_tree.py)
- Reuses the Management client + encrypted creds: [`app/services/mgmt_api.py`](../../app/services/mgmt_api.py), [`app/services/mgmt_creds.py`](../../app/services/mgmt_creds.py)

## Use it

1. Portal → **Access Automation**. Pick one of your saved **Management Servers** (a stored, encrypted
   credential is required — set one on the server's **Edit** page).
2. Enter the request: **source**, **destination**, and the service — either **protocol**
   (`tcp`/`udp`/`sctp`) + **port**, a named **service** (`icmp`, `GRE`, …), or an **application** site
   (`Facebook`). Precedence is application > service > protocol+port. Each endpoint has a **type**: the
   default `IP / CIDR / Any`, or a **typed object** — `Domain` (an FQDN, e.g. `alshawwaf.ca`, or
   `.alshawwaf.ca` for the domain *and* its sub-domains), `Access role`, `Dynamic object`,
   `Updatable object`, or `Security zone`. So you can ask, e.g., *"does host `10.1.1.222` have access to
   the domain `alshawwaf.ca`?"* (see [Typed objects](#typed-non-ip-sourcedestination) below). Name the
   **layer** to evaluate (optionally a **package**), and a **ticket id** to stamp on the change.
3. **Preview** (`POST /access-automation/{sid}/preview`) — read-only. The engine pulls the layer, runs
   `decide()`, and shows the minimal change: *already allowed (no-op)* / *widen rule N's source-or-dest
   cell* / *create a rule, placed `above`/`below` rule N* / *REVIEW* with the reason it couldn't decide.
   Type-ahead chips (`/{sid}/app-search`, `/{sid}/svc-search`) correlate a fuzzy app/service name to a
   real Check Point object before you commit to it.
4. **Apply** (`POST /access-automation/{sid}/apply`). With `publish:false` (the default) the change is
   made then **discarded** — a true dry-run that validates against the SMS with zero commit. With
   `publish:true` it commits. A "locked for editing" conflict can be resolved with
   `POST /access-automation/{sid}/take-over` (destructive; the UI confirms first).

## The decision engine

`decide()` is **pure** (no I/O) — it walks the parsed rulebase top-down honouring Check Point
**first-match** semantics, comparing every cell **by value** (IP/port intervals resolved through the
object dictionary), never by object name. The four outcomes:

- **NO_OP** — the first covering rule before any covering drop is an Accept → change nothing. The verdict is
  scoped to **this access layer** (Check Point Ordered Layers chain — a downstream layer can still restrict it).
- **WIDEN** — a reachable Accept is *exactly equal* to the request in two of {source, destination,
  service} and differs in the third → add the request's value to that **rule cell** (never to a shared
  group, which would widen every rule that references it).
- **CREATE** — nothing covers it → add a least-privilege Accept (`track: Log`, comment stamped with the
  ticket id). Placement is computed for first-match correctness: **above** any blocking deny it can fully
  resolve (an application/category is *carved out* above a rule that blocks it), **below** any more-specific
  rule, else grouped into a configurable **provisioned section** created just *above* the cleanup section —
  never *inside* it (Check Point's organize-by-section best practice). If the new allow would also shadow a
  more-specific deny **below** the one it overrides, that anomaly is flagged with an advisory. An
  **application/category** request scopes its destination to the predefined **Internet** object (App Control
  best practice), carrying a note that Internet is topology/blade-dependent.
- **REVIEW** — reserved for a request that can't be turned into a concrete change (an empty/unparsable
  service, or a typed endpoint that names no object) or an ambiguous application/service *name*. It is **not**
  a policy-review stop: the engine never hands a *resolvable* rule to a human — it reuses, widens, or creates.
  Inline ("Apply Layer") rules are pulled and recursed into; a Dynamic Layer (sk182252) is excluded as
  out-of-band but still acts as a placement floor.

**The deny is overridden by placement, not a stop.** A *resolved* covering/partial deny → CREATE the allow
ABOVE it so the access works (first-match then hits the allow); the reason names the deny. A deny it
**cannot** fully resolve (an infra object collapsed to its main IP, an opaque service category, a conditional
drop) is *not* overridden — it's noted and the new allow lands BELOW it.

**Opaque rules don't stop the flow.** A rule the engine *can't fully resolve* — an updatable feed (which
may itself contain the requested object), an unresolvable/negated cell, an over-cap wildcard, an opaque
app category, a non-Accept/Drop action — no longer halts the request with REVIEW. The walk **notes it as
a "possible match — review later" and continues** to the real NO_OP / WIDEN / CREATE. This is safe by
construction: a NO_OP writes nothing, and a new rule is always placed **below** any such opaque
possible-deny (and a WIDEN that would leap a rule over it is suppressed), so the firewall is never
weakened — the opaque rule keeps its first-match precedence. The notes ride along on the decision (and
the webhook/MCP result) so nothing is lost. (A *resolved* deny is different — it's overridden by placement,
above, not handed to a human.)

**Behaviour is tunable — data, not code (Settings → Access automation logic).** A one-click **profile**
(Conservative / Balanced = default / Aggressive / Autopilot) bundles the knobs; individually,
`aa_override_blocking_deny`, `aa_app_carveout`, `aa_prefer_widen`, `aa_emit_notes`, and `aa_ignore_conditions`
each govern one judgment call (defaults = the recommended behaviour), and `aa_rule_section` names the
provisioned section. The live decision tree is downloadable as `.drawio` / `.mmd` / `.dot` from
`/access-automation/decision-tree/{fmt}`.

## Typed (non-IP) source/destination

A source or destination isn't only an address — it can be a Check Point object that matches by a
*different identity entirely*: a **dns-domain** matches by FQDN/DNS, an **access-role** by identity, a
**security-zone** by interface, a **dynamic-object** by gateway-resolved name, an **updatable-object** by
a Check Point-curated feed. Switch either endpoint's **type** to one of these and the engine reasons in
that object's own space — the same way it already treats a service request as *ports* OR *an application*
(never confusing the two).

- **Each kind is its own match space.** A domain request is **provably disjoint** from a rule cell that
  holds only IP / role / zone objects (an IP object can never *be* a domain object), so it is never
  blocked or satisfied by one — it matches an `Any` cell, or a dns-domain object **equal to or a parent
  of** the requested FQDN (`.alshawwaf.ca` covers `alshawwaf.ca` and `www.alshawwaf.ca`). This is
  object-identity semantics: the engine reasons about the policy *as written*, not about runtime DNS
  resolution. The one uncertain cross-kind case is a domain request meeting an **updatable-object** cell
  (a feed like *Office365* can itself contain FQDNs) → that routes to **REVIEW**.
- **IP requests are unchanged.** A plain IP/CIDR request still treats every typed cell as opaque and
  never steps past it — the typed feature only adds new reasoning for typed *requests*; it never weakens
  the IP path.
- **Apply.** A missing **domain** or **dynamic-object** is created (`add-dns-domain` /
  `add-dynamic-object`) then placed; **access-role / security-zone / updatable-object** are **reuse-only**
  — they can't be fabricated from an access request (define them in Identity Awareness / the gateway
  topology / Check Point's repository first), so a missing one is reported, not invented.

## Inbound webhook (end-to-end automation)

`POST /access-automation/webhook` lets any ticketing system (ServiceNow, Jira, Remedy, curl …) POST an
access request and get back the decision — and, optionally, have it applied and written back.

- **Auth:** the shared secret must arrive as the **`X-DCSim-Token`** header, matching a webhook-scoped
  **API key** (Settings → API keys) or the legacy token (`DCSIM_WEBHOOK_TOKEN` / Settings). If neither
  is set the endpoint is **disabled (503)** — it never runs unauthenticated.
- **Body:** vendor-neutral JSON with generous aliases — `server_id` (which saved server), `layer`,
  `source`/`src`, `destination`/`dst`, `protocol`+`port` (or `service` / `application`), optional
  `source_kind`/`destination_kind` (default `ip`; or `domain` / `access-role` / `dynamic-object` /
  `updatable-object` / `security-zone` — then the value is the object identity, e.g. an FQDN), optional
  `package`, `ticket_id`, and `apply` (`true` → apply + publish; default → preview only).
- **Scope:** an optional allowlist (`DCSIM_WEBHOOK_SERVER_IDS` / Settings) restricts the token to
  specific server ids. A *malformed* allowlist **fails closed** (500) rather than degrading to allow-all.
- **Write-back:** the result is pushed to the caller's `callback_url` if supplied, else the built-in
  **ServiceNow Table API** adapter writes a work note to the incident (`DCSIM_SERVICENOW_*` / Settings).

## Security notes

- The publish webhook token grants policy publish on every allowed server — treat it as a top-tier
  secret; scope it with the server-id allowlist.
- **TLS is always verified**, on both the SMS session and every write-back HTTP call — there is no
  skip-verify path. The server's certificate is trust-on-first-use pinned (`ensure_pinned`) before the
  handshake; Management and ServiceNow credentials are stored **encrypted at rest**, never hardcoded.
- `execute()` does all work inside **one session** and publishes (commit) or discards on the dry-run /
  on any error — a half-applied change and its locks are always released, never left dangling.
- A truncated rulebase pull **fails loud** rather than deciding on a partial view (which could step over
  a covering drop it never loaded). New objects materialize at the full requested scope — a CIDR wider
  than one address becomes a **network** object, never silently narrowed to a `/32` host.
