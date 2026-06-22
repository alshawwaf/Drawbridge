# Access-automation — SBT lab validation runbook

**Goal:** confirm, against a live R82.10 Management server, that every `# VERIFY` web_api call the
access-automation engine emits has the exact spelling/shape the API expects — so `preview → dry-run →
publish` is *trusted*, not just demo-ware. The decision logic is unit-tested + adversarially audited; what
has never run live is the **write path** (object/rule creation, placement, widening, locks).

Run this once on the SBT lab and fill in the **Result** column. Anything that fails → note the real
spelling and we fix the one call.

---

## 0. Prep (15 min)

1. Lab SMS reachable from the box running Drawbridge (TLS 1.2+; cert pinned via the Management page).
2. In Drawbridge → **Layers & Gateways → Management** → add the SBT SMS (host, admin user, password;
   auto-trust or paste the cert). Run **Test connection**.
3. Pick a **scratch access layer** (or a scratch policy package) you can safely write to. Note its name.
4. Settings → confirm the read-only session reuse + write-session timeout are sane (defaults are fine).
5. Have **SmartConsole open** on the same SMS to eyeball what actually lands (and to create a lock for
   step F).
6. Every step below runs from **Layers & Gateways → <SMS> → Access automation**. The result panel has a
   **“web_api calls (N)”** expander — that trace is what you're verifying.

> Tip: do all of **A–E with “Dry-run apply (validate)” first** (it applies inside a session then
> *discards* — nothing is committed), then repeat the ones you trust with **Apply & publish**.

---

## 1. The `# VERIFY` calls (what's being checked)

| # | Call | Where | Shape to confirm |
|---|------|-------|------------------|
| 1 | `add-host` | create a /32 endpoint | `{name, ip-address}` (CP infers v4/v6 from the value) |
| 2 | `add-network` | create a CIDR endpoint | v4: `{name, subnet4, mask-length4}` · v6: `{name, subnet6, mask-length6}` |
| 3 | `add-service-tcp` / `-udp` | create a port service | `{name, port}` |
| 4 | `add-access-rule` | CREATE outcome | `{layer, position, name, source, destination, service, action:"Accept", track:"Log", comments}` |
| 5 | `set-access-rule … {field:{add: obj}}` | WIDEN outcome | `{uid, layer, source|destination|service:{add: <name>}}` — added to the **cell**, never a shared group |
| 6 | `position {above: <uid>}` / `{below: <uid>}` / `"bottom"` | placement | does `position` accept a rule **uid** (and name / number)? |
| 7 | `show-objects` (dedup) | reuse host/network/service | `{filter, ip-only, type, limit}` returns the existing object so we reuse not duplicate |
| 8 | `show-access-layer {uid}` | inline-layer cleanup | returns `implicit-cleanup-action` (`drop`/`accept`) |
| 9 | `add-host` with v6 | IPv6 endpoint | does `ip-address` accept a v6 literal, or is `ipv6-address` required? |

---

## 2. Trace plan (fill in Result)

For each: run it, expand **web_api calls**, and check the trace matches “Expected”. Then confirm in
SmartConsole (publish steps only).

| Step | Request (src → dst : svc) | Expected outcome + calls | Result |
|------|---------------------------|--------------------------|--------|
| **A. NO_OP** | a flow your layer already permits | `no_op`; **no** write calls | |
| **B. CREATE (dry-run)** | new src → new dst : tcp/443, nothing covers it | `create`; `add-host`×N (reused if present), `add-access-rule` above the cleanup; then **discard** (SmartConsole shows nothing) | |
| **C. CREATE (publish)** | same as B | rule committed **above the cleanup, below any more-specific rule**; objects reused not duplicated | |
| **D. WIDEN** | a src that differs from a rule matching dst+svc exactly | `widen`; `set-access-rule {source:{add:<host>}}` on **that rule's cell** (verify in SmartConsole the source cell gained one object, no other rule changed) | |
| **E. CREATE in inline layer** | a flow fully inside an “Apply Layer” rule's scope, not covered inside | `create` with **Inline layer: <name>**; `add-access-rule layer:<inline layer>` (rule lands inside the inline layer) | |
| **F. Lock conflict** | hold a lock in SmartConsole (start editing a rule), then Apply&publish | result shows **lock conflict + the holding session**; **Take over & release** frees it; re-preview works | |
| **G. Service types** | src → dst : `icmp` (Service field), then `sctp`/`GRE` | the rule references the **correct predefined/service object** (echo-request, etc.), no “unknown service” error | |
| **H. IPv6** | `2001:db8::5` → `2001:db8::9` : tcp/443 | v6 host/network created (call #9), rule committed; a v6 request is **disjoint from v4-only rules**, covered by Any/Any | |
| **I. Explicit deny** | a flow an explicit (non-cleanup) Drop covers | `review` (never silently overrides the deny) — unless override-deny mode is on | |

**Verdict to record per step:** ✅ exact match · ⚠️ works but spelling differs (note it) · ❌ rejected
(paste the API error).

---

## 3. If a call is rejected

The fix is almost always a one-line spelling change at the cited `# VERIFY` line in
`app/services/access_automation.py`. Capture: the **request body** Drawbridge sent (from the trace), the
**API error**, and the **correct** body (from SmartConsole's API “Copy as script” or the R82.10 API
reference). Send those three and we patch + re-test.

---

## 4. Bundle: security-zone topology (reducer #3 remainder)

Resolving security-zone rule cells needs gateway topology, which carries its own unvalidated spellings —
best confirmed in this same session, then we build the resolver behind the default-OFF
`aa_resolve_topology` toggle. While on the lab, capture from a gateway with zones configured:

- `show-gateways-and-servers details-level full` — per **interface**: the field name carrying the
  **security zone** (`security-zone-settings` → `specific-zone` / auto-calculated?) and the **network
  behind the interface** (`topology-settings` → `ip-address-behind-this-interface`,
  `specific-network`?).
- Note which interfaces are **“network defined by the interface IP/mask”** vs **“by routing”** vs
  **“not defined”** (the last two are unbounded → must stay REVIEW).

With those field names confirmed, the zone→networks join (under-approximation for ACCEPT only, never a
DROP) is a small, safe addition. Until then, security zones correctly route to REVIEW.

---

## 5. What's already proven (no lab needed)

The pure decision engine (`decide()`) is exhaustively unit-tested + twice adversarially audited:
four-outcome correctness, first-match/shadowing, inline-layer recursion, configurable aggressiveness, all
service types, IPv4+IPv6 (dual-band), wildcard + group-with-exclusion resolution, and the
never-over-grant / never-under-deny invariants. This runbook only validates the **web_api spellings** on
the write path.
