# Full access-rule column support — plan & directive

> **Status:** ACTIVE (started 2026-06-26). This is the authoritative plan for completing the
> decision-and-grant engine with full column coverage. The detailed, spec-grounded per-column design
> and test matrix are produced by the design-research pass and recorded below as they land.

## Directive (from the user, do not lose sight)

This app **stays a decision-and-grant engine** — it is NOT becoming a policy manager. We **keep this
version** and **complete the picture** so that a **ServiceNow ticket** (and the MCP request / webhook)
can carry information about **every access-rule column**, not just source/destination/service and an
Accept-or-Drop action.

- A ticket might request the **VPN** column be assigned to a **specific community**.
- A rule must support **all action options**, not only Accept/Drop.
- We must support: **TIME, CONTENT, ACTION (all options), INSTALL-ON, VPN**.
- **Consider every supported option in the CP R82.10 API and actually use them.**
- **Test every single scenario — especially ACTION, CONTENT, and TIME.**
- **Verify the INSTALL-ON option.**
- **No room for failure.**

The broader **policy-manager** capabilities (browse/search/move/reorder/object-CRUD/sections/layers/
install-policy — see the gap analysis) are a **separate future app**, explicitly NOT this work.

## Scope of THIS work

Add full column coverage to the existing grant/revoke/amend flows:

| Column | What the ticket can express | Engine impact |
|---|---|---|
| **action** | Accept / Drop / Reject / Ask / Inform (+ Apply Layer), with action-settings (limit, UserCheck interaction, captive portal) | the created rule's action is no longer fixed to Accept(grant)/Drop(revoke) |
| **time** | a time object / window the rule is restricted to | match-gating (today → REVIEW); write on create |
| **content** | Content Awareness data type(s) + direction | match-gating; write on create |
| **install-on** | the gateway(s) the rule installs on ("target") | scope; write on create; **verify live** |
| **vpn** | a VPN community (+ directional) | match-gating; write on create |
| (already done) | name / comment / tags / track-type | via `amend_access_rule` |

## Where it lands

- **Request model** — `AccessRequest` fields + `ticketing.build_request()` + webhook `parse_payload()`
  field aliases (so a ServiceNow ticket carries each column).
- **Apply** — `_apply()` / `_apply_removal()` write each column on `add-access-rule` (and `amend` for edits).
- **Decision engine** — `decide()` where the action and the match-gating columns change the outcome
  (a non-Accept action; a time/content/install-on/vpn restriction).
- **Agent surface** — `decide_access` / `apply_access` / `amend_access_rule` MCP params + docstrings + the
  suggested system prompt.
- **Tests** — an exhaustive per-option matrix per column (the QA battery `aa_qa.py` + unit tests),
  especially action/content/time; live verification on the lab (install-on especially).

## BUILD PLAN

> Spec-grounded, decisive. Five columns: **action, content, time, install-on, vpn**. Built in that
> order. All object references are **REUSE-ONLY** (validate-by-name, never create) except `action`
> companions. Everything not provable stays **REVIEW**. Backward compatibility is a hard gate: a request
> with **no** new fields must produce a **byte-identical** `add-access-rule` payload to today.

### USER DECISIONS (2026-06-26 — override the open questions below)
1. **Apply Layer = ALWAYS CREATE**, even when it references a **dynamic** layer (no toggle, no REVIEW). Validate the inline-layer NAME resolves to a real layer (ordered or dynamic) and error cleanly if not; otherwise create the divert rule directly. (Supersedes the "REVIEW unless toggle" default.)
2. **UserCheck interaction = DEFER** in v1. Ask/Inform fully supported with the gateway-default UserCheck; the ticket can't pick an interaction object yet (unverified API shape).
3. **TIME = reuse-only NOW + create-behind-a-toggle.** v1 ships reuse-only solidly; ALSO add an `app_settings` toggle (default OFF) that enables creating a simple time window — its `add-time` nested shape MUST be live-verified before the toggle is documented/enabled.
4. **VPN directional = REJECT** in v1 (clear "not supported" error). Community assignment (Any / star / meshed / remote-access / All_GwToGw) fully supported.

---

### 1. Per-column summary

#### ACTION — the rule verdict + companions

| API field | Type / write shape | Notes |
|---|---|---|
| `action` | **string**, exact CP casing | Enum: `Accept` `Drop` `Reject` `Ask` `Inform` `Apply Layer` (writable); `User Auth` `Client Auth` read-only/legacy. Note the **space** in `Apply Layer`. |
| `action-settings` | **object** `{enable-identity-captive-portal:bool, limit:"<name>"}` | Spec types it `string` but the real wire shape is an object (confirmed by spec request/response examples). Emit only when non-default; strip from any deny. |
| `inline-layer` | **string** (name/UID) | Required **iff** `action=="Apply Layer"` (SMS business rule, **not** in spec `required[]` — enforce client-side). Forbidden otherwise. |
| `user-check` | **object** — **UNVERIFIED write** | Spec gives **zero** access-rule example; `preferred-language` lives only in global-properties. **Drop from v1** (default language is used). Read shape `{confirm,frequency,interaction}` is correct & unchanged. |

- **Request fields** — `AccessRequest.action` already exists (`access_automation.py:478`) but is **dead** on write (`_apply` hardcodes `Accept` at `:2602`); wiring it live is the core change. Add `action_settings_limit:str=""`, `action_settings_captive_portal:bool=False`, `inline_layer:str=""`.
- **Apply mapping** — `_apply` CREATE: replace literal `"action":"Accept"` with `req.action`; if `Apply Layer` set `inline-layer` (validate name-exists, never auto-create); build `action-settings` only when non-default and only on allowing actions; pass the requested action into `_naming_ctx` (`:2588`) so a `{action}` template renders the real verdict. WIDEN/removal paths unchanged (revoke stays Drop-hardcoded).
- **Engine reasoning** — map `req.action` → intent class (ALLOW/CONDITIONAL-ALLOW/DENY/DIVERT/LEGACY-forbidden). NO_OP only when a covering, fully-resolved rule has the **same effective verdict**. **WIDEN gate (the load-bearing fix at `:1649`):** only an Accept request may widen — a Drop/Reject/Ask/Inform/Apply-Layer request must skip widen and fall to CREATE. Ask/Inform = never-reusable (CREATE only, flagged). Apply Layer → default **REVIEW** unless `inline-layer` names a real non-dynamic layer **and** a toggle is set. Read side needs **no** change (`is_resolved_action`, `is_drop`-folds-Reject already correct).

#### CONTENT — Content Awareness data types + direction + negate

| API field | Type / write shape | Notes |
|---|---|---|
| `content` | **list of NAME/UID strings** | Reuse-only data-type objects; rule matches if **ANY** listed type detected (OR). `["PCI - Credit Card Numbers","Source Code"]`. |
| `content-direction` | **string enum** `any` \| `up` \| `down` | Exactly these three (spec-verified); reject anything else up-front. Default `any`. |
| `content-negate` | **boolean** | Default false → **omit** when false (minimal payload). |

- **Request fields** — `content:Optional[list[str]]=None`, `content_direction:str="any"`, `content_negate:bool=False`; property `has_content = bool(self.content) or self.content_negate`.
- **Apply mapping** — when `req.has_content`: resolve each name via new reuse-only `_resolve_content_objects` sweeping `_CONTENT_DT_TYPES` = (`data-type-patterns, -keywords, -file-attributes, -group, -compound-group, -traditional-group, -weighted-keywords, -file-group`) — **NOT** the invalid `data-types` literal — with a final no-type `show-objects` fallback accepting an exact-name object whose `type` startswith `data-type`. Write `content` (list) + `content-direction`; emit `content-negate` only when true. WIDEN must **not** write content (assert/skip).
- **Engine reasoning** — read/reason side is already correct (`_rule_conditions:887` flags `data`). **Net-new:** an early branch — when `req.has_content`, **suppress reuse/widen/NO_OP and force CREATE** (content-equality across cells is a documented non-goal, stays REVIEW-conservative). Pre-validate names in `_correlate` (`:2773`, runs in both preview & execute) → clean REVIEW with "did-you-mean" candidates, never a partial write.

#### TIME — time-restriction column (reference-only)

| API field | Type / write shape | Notes |
|---|---|---|
| `time` | **list of NAME/UID strings** | Time objects / time-groups; rule matches if **ANY** window active (union). `["Off-Work","Weekend"]`. **Whole-list REPLACE** on set (no `{add}/{remove}`). |

- **Request fields** — `time_objects:list[str]=field(default_factory=list)` (empty = no restriction). `create_time_spec` only if the create-toggle ever ships (v1 = **REUSE-ONLY**; create deferred — name ≤11 chars + unverifiable nested recurrence shape).
- **Apply mapping** — resolve every name via `show-objects {type:"time"}` **and** `{type:"time-group"}`, exact-name match, atomic pre-flight (validate ALL before any write). Guard `if time_names: payload["time"]=...` (the `{k:v if v is not None}` filter at `:2609` keeps `[]`, so an empty restriction must be explicitly omitted). Inverse for CREATE = delete-rule (object left in place). **Exporter fix:** `mgmt_export.py:96` declares `time` kind `"str"` (scalar) — wrong for a list cell; change to a list kind or TF/Ansible render a single string.
- **Engine reasoning** — read side already correct (`_cell_is_any` at `:864/885`). Add `_time_set(rule)` compare: a time-restricted request NO_OPs/widens **only** against an Any/Policy-broader rule (with a "grants 24/7" note) **or** an exactly-equal time set; a different set → CREATE; a time-group is **opaque** → never assume coverage. Removal: relax the conditional-REVIEW gate (`:1922`) to permit DISABLE only when conditions == `("time",)` **and** the time set matches exactly; otherwise REVIEW.

#### INSTALL-ON — the enforcing gateway(s) ("target")

| API field | Type / write shape | Notes |
|---|---|---|
| `install-on` | **list of NAME/UID strings** | Gateway / cluster / gateway-group objects; **REPLACE** semantics (no add/remove). Omit → default **`Policy Targets`** (Any gateway, UID `6c488338-…-c476`, type `Global`). |

- **Request fields** — `install_on:list[str]=field(default_factory=list)` + helper `install_on_is_default()`. `_norm_install_on` collapses sole `any/all/*/Policy Targets` (any case) → `[]` (omit), but keeps real gateways in a mixed list. **`change_log.snapshot_request` omits it today — add it** so rollback/re-apply preserves scope.
- **Apply mapping** — `resolve_install_on_target` uses **`show-objects` by name** (exact-name match + eligible-`type` gate) — **NOT** `show-gateways-and-servers` with a `filter` (that op has **no** `filter` param). Eligible types: `simple-gateway, simple-cluster, CpmiGatewayCluster, CpmiClusterMember, CpmiVsClusterNetobj, CpmiVsxClusterNetobj, CpmiHostCkp, CpmiGatewayPlain, CpmiVsClusterMember`; plus a `type:"group"` fallback. A host that exists but isn't a gateway → hard error. `if targets: payload["install-on"]=targets`.
- **Engine reasoning** — read side already flags install-on as conditional (`:889`). Add `ParsedRule.install_on_names`, `install_on_any`, `install_on_opaque` + helper `_rule_covers_targets`: a request naming gateway(s) NO_OPs/reuses only on a rule effective on **every** requested gateway (Policy-Targets covers all → NO_OP with "broader" note; disjoint concrete sets → CREATE; any group/opaque → CREATE). A concrete drop disjoint from the requested gateways is **out-of-path**; opaque/group drop stays conservative. `_rule_covers_targets` stays **outside** the `ignore_conditions` gate (the user asked for a specific gateway). **Decide stays pure — gateway validation happens only on apply** (preview shows a best-effort exists flag via `_install_on_preview`).

#### VPN — the VPN match column (reuse-only)

| API field | Type / write shape | Notes |
|---|---|---|
| `vpn` | **list of NAME/UID strings** | Communities (star/meshed/remote-access) + literals `Any`, `All_GwToGw`. **REPLACE** (no `{add}`). `[]` = explicit Any; `None` = don't touch. **Directional pair shape is undocumented → REJECT, don't guess.** |

- **Request fields** — `vpn:Optional[list[str]]=None` (after `svc_set`). Aliases `vpn/vpn_community/vpn_communities/u_vpn`.
- **Apply mapping** — three sites: CREATE (`if req.vpn: payload["vpn"]=req.vpn`, delete-rule inverse covers it); existing-rule **amend** (`amend_execute:3199` — add `vpn` to `_AMEND_API_FIELD:3176` + `_AMEND_REVERT_FIELDS:3300`; capture prior list, REPLACE, inverse = full prior list incl. `[]` for Any); layer editor (`build_set_rule_op` — use **`if "vpn" in changes`** membership, not `.get()` truthiness, or a `vpn:[]` Any-edit is silently dropped). Widen = read-list-union-REPLACE (never `{add}`). `_structure_rule:459` + exporters already emit it — **no read/export change**.
- **Engine reasoning** — match side already correct (VPN-conditional via `_cell_is_any:883`). **Correction:** a VPN-conditional rule in the removal path is **REVIEW** today (`:1932`), not auto-DISABLE; the safe revoke baseline stays REVIEW. New: DISABLE only when `req.vpn` set **and** the in-path ACCEPT's vpn equals that **exact** set **and** otherwise sole-and-exact; any mismatch → REVIEW or unconditional Drop-above. Validate each community via the correct `show-vpn-community-{star,meshed,remote-access}`; whitelist `Any`/`All_GwToGw`. **Amend contract change:** `amend_execute` + `mcp_tools.amend_access_rule` docstrings ("NEVER match columns") must be amended — `vpn` is the lone reuse-only exception — and the amend empty-guard must include `vpn`.

---

### 2. Cross-cutting design (do once, not five times)

**Shared request-model change** — extend `AccessRequest` (`access_automation.py:468`, plain `@dataclass`,
not frozen → each new field carries a default so field-ordering stays valid). All five columns ride
through the **one** `common` dict in `ticketing.build_request()` (`ticketing.py:170`) — critical because
`build_request` returns via **three** constructors (application / service / protocol+port); a field added
to only one branch is silently lost for the others. One pass:

| Wire point | One change covering all columns |
|---|---|
| `AccessRequest` (`:468`) | add: `action`(exists) + `action_settings_limit/_captive_portal/inline_layer`, `content/content_direction/content_negate`, `time_objects`, `install_on`, `vpn`; helpers `has_content`, `install_on_is_default`, `_canonical_action`, `is_conditional_action`. |
| `build_request` (`:149`) | add kwargs for every column; **merge into `common`** (`:170`); canonicalize+validate action against the allow-list; normalize content/time/install-on/vpn (string-or-list → clean list, strip, dedupe, drop blanks); reuse the `len>256 / ord<32` name guard (`:144`). |
| `parse_payload` (`:183`) via `_first` (`:48`) | add webhook **aliases** + ServiceNow `u_*` aliases for every column; booleans through `_TRUE` (`:29`). |
| `mcp_tools._build` (`:100`) | add the same kwargs and **forward** (currently a fixed positional call — extend it or fields drop silently). |
| `mcp_tools.decide_access/apply_access` (`:125/:183`) | typed kwargs per column (docstrings drive the FastMCP schema). `remove_access` (`:227`) gets `time_objects`/`install_on`/`vpn` for target-narrowing but **no** `action` (revoke verdict is engine-chosen). `amend_access_rule` (`:285`) gets `vpn` only. |
| `app/routers/access_automation.py:169` + UI form | the Pydantic body model **and** the `build_request` call must carry all columns or UI submissions can't set them. |
| `change_log.snapshot_request` (`change_log.py:37`) | **hand-built dict** — explicitly add every new key (content/direction/negate, time_objects, install_on, vpn) so revert/re-apply reconstructs the cells. |

**Shared apply change** — one CREATE path (`_apply`, payload at `:2595`, `add-access-rule` at `:2609`):
write each column **after** src/dst/svc, each behind its own non-default guard (omit when default so the
no-new-fields payload is byte-identical to today). Each reuse-only column resolves through the **same**
validate-by-name pattern (`lookup_typed_object`, `:2306`): exact-name match, atomic pre-flight, hard
`MgmtError` with "did-you-mean" candidates on miss, **never** auto-create. The CREATE inverse is the
existing `delete-access-rule {created_uid}` (`:2618`) — it covers **all** columns; created/reused objects
are left in place. For the **layer-editor / amend** REPLACE path, capture prior values via
`show-access-rule details-level full` **before** the write and replay them atomically in **one**
`set-access-rule` (store NAMES not UIDs for portable rollback). Extend `build_set_rule_op`
(`mgmt_api.py:742`) with explicit `if <key> in changes` branches (membership, not truthiness) so empty-list
"reset to Any" edits are honored.

---

### 3. Build sequence (ordered phases — each: build → test → **commit after green + adversarial review**)

> Every phase ends with the full `tests/test_aa_scenarios.py` regression battery **plus** the new
> phase tests green, then an adversarial self-review, then a local commit (the watcher auto-pushes).
> The cross-cutting request/apply scaffolding (§2) lands incrementally with Phase 1 and is reused after.

1. **ACTION first ✅ DONE (commit pending)** — it changes the **create contract** most (the literal `Accept` is the only verdict
   today; everything downstream assumes it). Build: the `action` allow-list + canonicalizer, `inline-layer`
   required-iff rule, `action-settings` builder, the WIDEN intent-gate (`:1649`), `_canonical_action` /
   `is_conditional_action`. Test: the full ACTION matrix (§4) incl. the corrected WIDEN gate + Apply-Layer
   REVIEW gating. **Commit after green + adversarial review.**
2. **CONTENT** — reuses the §2 reuse-only resolver pattern; pure write+request side (read side already
   correct), self-contained, no live dependency. Build the `_CONTENT_DT_TYPES` sweep + the force-CREATE
   `has_content` branch + `_correlate` pre-validation. Test the CONTENT matrix. **Commit after green + review.**
3. **TIME** — same reuse-only shape as content; adds the exporter kind fix + the removal-gate relaxation
   for `("time",)`-only. Test the TIME matrix incl. the exporter list round-trip. **Commit after green + review.**
4. **VPN** — reuse-only with the amend-contract change (the one match column `amend` may touch) +
   directional-reject; touches `amend_execute` rollback. Test the VPN matrix incl. amend/revert + Any-restore.
   **Commit after green + review.**
5. **INSTALL-ON last** — it **needs live lab verification** (the highest-risk assumption: whether the
   generic `show-objects` returns gateway objects at all on R82.10) before it can ship safely. Build the
   `resolve_install_on_target` show-objects path + the `ParsedRule` install-on fields + `_rule_covers_targets`
   + the disjoint-drop out-of-path refinement. Test the INSTALL-ON matrix, **then run the live-lab
   checks below**, then **commit after green + review.**

---

### 4. Consolidated EXHAUSTIVE test matrix

> **`[LIVE]`** = must be verified against the lab SMS (`uvo13j7ehrw0f57q2ae.vm.cld.sr`, server id 1),
> not just mocked. Every column needs **one real apply → show → verify → rollback** `[LIVE]`.

**ACTION**
- `build_request` defaults to `Accept` when omitted (back-compat); canonicalizes `accept/ACCEPT/ "accept" /drop/reject/ask/inform`; `apply layer / APPLY LAYER / "Apply  Layer"` (double-space) → exact `Apply Layer`.
- Rejects `User Auth / Client Auth / Allow / Permit / "accept;drop" / garbage / "" ` with ValueError — **never** a silent Accept.
- `Apply Layer` **without** `inline_layer` → ValueError; `Accept/Drop/Ask` **with** `inline_layer` → ValueError.
- New fields propagate through **all three** `build_request` return shapes (app / named-service / proto+port) — regression for the `common` merge.
- ENGINE: add Accept/covering Accept → NO_OP; add Drop/covering Drop → NO_OP; add Reject/covering Drop → NO_OP (is_drop folds reject); add Drop/covering Accept → **not** NO_OP (verdict flip → deny-above/CREATE/REVIEW).
- ENGINE WIDEN gate (corrected): add Drop, equal-in-2-dims Accept candidate → **NOT** widen → CREATE/deny (verifies `:1649`); add Ask → CREATE conditional, flagged.
- ENGINE Apply Layer: valid non-dynamic layer + toggle → CREATE divert; toggle unset → REVIEW; dynamic layer → REVIEW + golden-rule note; non-existent layer → clean error (not 500).
- APPLY: each verdict writes the right `action`; `Ask`+captive → `action-settings:{enable-identity-captive-portal:true}`; `Accept`+limit → `action-settings:{limit:…}` after name-exists; captive on a Drop → stripped. `_naming_ctx` renders the requested verdict. **No** `user-check` key emitted on any payload (v1 deferred).
- ROLLBACK: CREATE of any verdict → delete-rule; Apply-Layer inverse deletes only the parent (inline layer survives).
- **`[LIVE]`** apply each verdict (Accept/Drop/Reject/Ask/Inform/Apply-Layer) → show → verify → rollback.

**CONTENT**
- `build_request`: list / comma-string / semicolon-string → clean trimmed list; direction `any/up/down` (case-insensitive, trimmed); `upload/both/sideways/""` → ValueError; negate via `_TRUE`; name `len>256` or control char → ValueError; no content args → `has_content` False, byte-identical payload.
- `parse_payload`: every alias (`data_type/data_types/content_type/u_content`, `data_direction/u_content_direction`, `data_negate/u_content_negate`) populates the request.
- `_correlate`/preview: unknown data-type → REVIEW with candidates, **zero** `add-access-rule` calls; one-of-many unknown → whole REVIEW, no partial write.
- ENGINE: request with content vs in-path content-Any Accept covering src/dst/svc → **not** NO_OP → CREATE; request with content matching the same single data-type as a content-gated Accept → still **not** NO_OP (equality is a non-goal). Regressions: content-gated accept/drop read behavior unchanged.
- APPLY: `["PCI…"]`+`up` → `content:[…], content-direction:up`, negate omitted; `["A","B"]`+`down`+negate → all three; no content → no content keys. Resolver sweeps each `_CONTENT_DT_TYPES`, group resolves, predefined resolves via no-type fallback; **assert it never passes `type:"data-types"`**. WIDEN must not write content.
- `build_set_rule_op`: `{content:["X"]}` → full list (not add/remove); direction/negate branches + summary.
- `mgmt_export`: a content+direction+negate rule exports to TF + Ansible + clish with all three.
- **`[LIVE]`** confirm `PCI - Credit Card Numbers` / `Source Code` return a `data-type-*` type (validates the fallback prefix check); confirm `set-access-rule` accepts a content **list**. Then apply→show→verify→rollback a content rule.

**TIME**
- Reference one / multiple / a time-group (resolved via `type:"time-group"`); unknown → MgmtError before any write + candidates; mixed known+unknown → atomic fail, nothing written; duplicates deduped; single string → list; webhook comma-string + JSON list + aliases (`u_time/time_object/window`).
- Empty/`[""]`/`["Any"]` → **no** `time` key (assert the `{k:v if v is not None}` filter does not leak `[]`); service & proto branches both carry `time_objects` (common-dict regression); MCP `_build` forwards it (positional-drop regression).
- ENGINE: time-restricted request vs unconditional Accept → NO_OP with "grants 24/7" note; vs a **different** time set → CREATE; vs **equal** set → NO_OP; vs a superset **group** → CREATE (opaque). Regressions: unrestricted request vs time-restricted accept → CREATE (conditional_skip); vs time-restricted drop → allow-below + uncertain_deny. WIDEN suppressed for a time request.
- Layer editor: set/clear/change time → whole-list REPLACE; inverse = full prior list; `[]` clears to Any; `"time"` in `_RULE_EDIT_FIELDS`; string-not-list → coerced/rejected cleanly.
- REMOVE: `time_objects` matching the sole+exact `("time",)`-only grant → DISABLE (requires relaxing `:1922`); different window → REVIEW; unrestricted revoke vs a time-restricted grant → REVIEW (ambiguous); grant with extra conditions (`("time","VPN")`) → REVIEW.
- **Exporter bug:** a time-cell rule exports as a **LIST** (not scalar) in TF + Ansible after the `mgmt_export.py:96` kind fix; two-time-object round-trip.
- **`[LIVE]`** apply→show→verify→rollback a time-restricted rule referencing a real lab time object.

**INSTALL-ON**
- `_norm_install_on`: `None/""` → `[]`; `GW` → `["GW"]`; `GW1, GW2` → list; dedupe order-preserving; sole `any/ALL/*/Policy Targets` (any case) → `[]`; `" , , "` → `[]`; **mixed** `GW1, any, GW2` → `["GW1","GW2"]` (default token dropped, reals kept); `len>256` / control char → ValueError.
- `build_request` threads via `common` across all branches; `snapshot_request` includes `install_on`; `parse_payload` aliases (`install_on/targets/gateways/gateway/u_install_on/u_targets`), comma + JSON.
- `_rule_covers_targets`: Policy-Targets covers any → True; `[GW1,GW2]` covers `[GW1]` → True; covers `[GW1,GW3]` → False; group either side (opaque) → False; exact match → True.
- `resolve_install_on_target`: exact name + eligible type → name; substring-only (`GW` returns `GW2`, no exact `GW`) → raise; wrong type (host) → raise; UID → canonicalize to name; group via `type:"group"` → name; not found → MgmtError. **Assert it never sends `filter` to `show-gateways-and-servers`** (spec-contract guard).
- ENGINE: req `["GW"]` vs Policy-Targets Accept → NO_OP + "broader" note; vs disjoint concrete `["GW1"]` → CREATE; subset-not-satisfied `["GW1"]` for req `["GW1","GW2"]` → CREATE; covering drop on a **different** concrete gateway → out-of-path; drop on a **group** (opaque) → conservative conditional-deny; group target req → never reuse, CREATE. `ignore_conditions` does **not** relax `_rule_covers_targets`.
- APPLY: default → **no** install-on key (byte-identical), inverse delete-only; `["GW"]` → written + show round-trip; multi-element; non-existent → MgmtError, session discarded, no 500; one valid + one invalid → whole apply fails (transactional); host-named-like-gateway → not-eligible error; group → written. WIDEN guard: a WIDEN reached with non-default `req.install_on` → defensive MgmtError, nothing written.
- Preview makes **no** SMS call to validate the gateway (mock asserts `resolve_install_on_target` not invoked in preview).
- **`[LIVE]` (highest priority)** on the lab SMS:
  - run `show-objects filter="GW"` (and `show-gateways-and-servers` **unfiltered**) → confirm the exact gateway name `GW` (10.1.1.111) and its `type` (expected `simple-gateway`) so the type-gate matches real data;
  - **confirm `show-objects` (no type) returns gateway objects at all** on R82.10 — *if not*, fall back to paginated unfiltered `show-gateways-and-servers` + client-side match (still no `filter`). This is the single highest-risk assumption — verify before shipping;
  - dry-run apply `install-on:["GW"]` (validate then discard) → `show-access-rule` → confirm the `[{uid,name,type,domain}]` readback shape;
  - confirm `set-access-rule install-on:["Policy Targets"]` resets a scoped rule (REPLACE semantics) before exposing it in the layer editor;
  - full apply→show→verify→rollback of a GW-scoped rule.

**VPN**
- CREATE: `None` → no vpn key (Any, not flagged); `[]` → omit/Any; `["MyIntranet"]` (star) / `["MyMesh"]` (meshed) / `["RemoteAccess"]` / `["All_GwToGw"]` (whitelisted) / `["A","B"]` (OR) → written + correct type round-trip + VPN-conditional.
- AMEND: Any→`["MyIntranet"]` (inverse `[]`, verify `_amend_meta_ok` allows `[]`); `["A"]`→`["A","B"]` (union-REPLACE, inverse `["A"]`); narrow; `["A"]`→`[]` (back to Any, inverse `["A"]`).
- Validation: unknown → error+candidates before any write; mixed known+unknown → whole write rejected; **directional `{from,to}` → rejected** ("directional VPN not supported"), no guessed payload.
- Webhook: comma-string, `u_vpn` alias, non-list/non-string scalar → clean 400 (not 500); blank/whitespace members stripped → `[]`; case-sensitivity (`"myintranet"` ≠ `"MyIntranet"`) → miss → error.
- MCP `amend_access_rule(vpn=…)`: CREATE-type change → targets created uid; WIDEN/DISABLE change → refused (created-only); publish gate off → refused; all-None incl. vpn → "nothing to change" (empty-guard includes vpn).
- ENGINE: community-scoped Accept does **not** NO_OP/reuse a request with `vpn=None` or a different community → conditional_skip → CREATE; community-scoped drop → noted, allow-below. REMOVE baseline: VPN-conditional in path → **REVIEW** (not DISABLE); new exact-match logic: `vpn=["A"]` vs sole+exact `vpn==["A"]` → DISABLE; `["B"]` or `None` → REVIEW/Drop-above.
- `build_set_rule_op`: `["A","B"]` → `vpn:["A","B"]`, summary `vpn → A,B`; **`[]` → MUST emit `vpn:[]`** (membership test, summary `vpn → Any`) — assert it is **not** silently dropped; unknown community via editor → SMS dry-run 400 surfaced (document the editor doesn't pre-validate like the AA path).
- Export: star/meshed/remote-access/`All_GwToGw` → name list; TF key `vpn_communities`, Ansible/clish names; directional/opaque member shows type, not a fabricated name.
- **`[LIVE]`** apply→show→verify→rollback a community-scoped rule referencing a real lab VPN community; confirm `set-access-rule vpn:[]` restores Any.

---

### 5. Open questions / risks

- **`[LIVE]` (INSTALL-ON, highest risk):** does generic `show-objects` (no `type`) return gateway objects on R82.10? Some versions hide infra objects — if so, the resolver must fall back to paginated unfiltered `show-gateways-and-servers`. **Confirm before INSTALL-ON ships.** Also confirm the exact lab gateway name `GW`/type and whether the SMS's own object is install-on-eligible.
- **`[LIVE]` (INSTALL-ON):** confirm `add-access-rule` accepts `install-on` as a **NAME** array (not only UID) and the standard-detail readback object shape; confirm `set-access-rule install-on:["Policy Targets"]` is the correct reset.
- **`[LIVE]` (CONTENT):** confirm predefined data-types (`PCI - Credit Card Numbers`, `Source Code`) return a `data-type-*` `type` (validates the no-type fallback prefix check); confirm `set-access-rule` accepts a content **list** (and whether an `{add}/{remove}` sub-op is honored) before relying on the full-list editor write.
- **`[LIVE]` (TIME):** the v2.0.1 processed spec **flattens** the `add-time` nested recurrence shape (`hours-ranges/recurrence/start/end`) to bare strings — a doc artifact. **Do not ship time-object create** on this evidence; if the create-toggle is ever enabled, verify the nested shape against a live `add-time` first. v1 = reuse-only avoids this entirely.
- **USER decision — `user-check` write (ACTION):** the spec gives **zero** access-rule example and `preferred-language` lives only in global-properties. **Recommend dropping it from v1** (default language is used, costs nothing). Alternative: gate behind a live `add-access-rule` round-trip that proves the accepted key. Needs a go/no-go.
- **USER decision — Apply-Layer create gating (ACTION):** creating a divert rule is structural (needs an existing non-dynamic inline layer + human placement). Default **REVIEW**; promote to CREATE only behind a toggle (mirroring `override_blocking_deny`). Confirm the toggle is desired vs always-REVIEW.
- **USER decision — TIME create-vs-reuse:** v1 ships reuse-only. Auto-creating short-named (≤11-char) time objects from ticket free-text is deferred behind an `app_settings` toggle (mirrors the security-zone toggle). Confirm reuse-only is acceptable for v1.
- **Layer-editor vs AA-path validation inconsistency (VPN/CONTENT/INSTALL-ON):** the AA path name-resolves before writing; the layer editor (`build_set_rule_op`) relies on the SMS dry-run 400. Decide whether to route editor writes through the same validator for parity (recommended) or accept the dry-run surfacing.
- **INSTALL-ON semantics:** a request naming a gateway is a **pure write-through** of the named target (recommended) — the engine does **not** infer install-on from src/dst topology. Confirm.
- **Group-target test coverage (INSTALL-ON):** the lab may lack a gateway network-group object; the opaque-group path is unit-only until one exists (or seed via the SBT Lab preset).

---

## Round 3 — re-validation (2026-06-26)

Ran the 5-lens adversarial validation a SECOND time over the round-1-fixed code. It raised 25 / confirmed 22 — several were regressions introduced by the round-1 "typed show-objects" resolver. All confirmed findings fixed (commit follows this section), **885 tests + aa_qa 40/40**:

- **HIGH #6 — install-on resolver was wrong.** CPMI gateway classes (`CpmiGatewayCluster`, …) are NOT valid `show-objects` `type` filters (silently swallowed), so a real cluster gateway was false-rejected. **Fix:** install-on, VPN communities and limit objects now resolve via their DEDICATED list commands (`show-gateways-and-servers` / `show-vpn-communities-meshed`+`-star` / `show-limits`), exact-name match. Data-types (content) + time objects stay on typed `show-objects` (they ARE in the object index). The resolver is now BEST-EFFORT: if a class is not enumerable on this version (every command/typed-query errors) the name passes through and the SMS validates it at write (the apply is an atomic pre-flight — a genuinely bad name still discards the whole session). This **also resolves** the round-1 `[LIVE]` install-on risk (no longer depends on whether `show-objects` returns gateways) and #3 (a network `group` no longer false-passes install-on — it never appears in `show-gateways-and-servers`).
- **HIGH #1/#11/#13/#14/#19/#20 — content/vpn "Any" not normalized.** `content=["Any"]`/`vpn=["Any"]`/`install-on=["Policy Targets"]` read as a restriction (forced a phantom CREATE) the apply layer then wrote empty. **Fix:** normalized at the ENGINE boundary in `AccessRequest.__post_init__` (`_strip_gating_wildcards`), so every construction path (webhook/MCP/portal/direct) agrees; a negate over only "Any" is dropped; `build_request` strips "Any" before the negate guard and rejects negate-over-Any loudly.
- **HIGH #10 — conditional verdict leaped an opaque possible-deny.** `_decide_nonaccept` anchored Ask/Inform/Apply-Layer ABOVE the first in-path rule even when that rule was an opaque/partial possible-deny → first-match override of an unmodeled block. **Fix:** mirror the Accept path's `uncertain_deny` — a conditional is anchored ABOVE only a rule we can prove safe to leap; an opaque/partial possible-deny floors it at the section bottom + flags.
- **MEDIUM #18 — webhook bare `action` alias broke back-compat.** A ServiceNow ticket's own unrelated `action` field hard-failed the request. **Fix:** dedicated verdict fields (`verdict`/`u_action`/`cp_action`) are strict; the bare `action` is honoured only when it names a real verdict, else defaults to Accept (`_resolve_webhook_action`).
- **LOW/NIT:** WIDEN `_apply` now self-defends against a restricted request (#8); `_validate_inline_layer` re-raises a transient `show-access-layers` failure instead of asserting "no such layer" (#4/#12/#22); action-settings (limit/captive) rejected on Drop/Reject/Apply-Layer rather than silently dropped (#16); audit snapshots carry `action_settings_limit`/`captive_portal` (#5/#15); typed reuse query bumped 50→200 to avoid an exact name lost behind a crowded substring page (#9/#17).

### Still deferred after round 3 (tracked, NOT bugs)
- **#21 — mgmt_export does not re-render action-settings.** A rule created with a UserCheck limit / captive-portal exports (TF/Ansible/CLI/API) without the `action-settings` column → fidelity loss on export round-trip. Needs the `show-access-rulebase` action-settings field shape (a `[LIVE]` check) before rendering; LOW (export completeness, not AA correctness).
- The `[LIVE]` lab pass for every column (one real apply→show→verify→rollback each) remains the highest-value next step — especially confirming the dedicated list-command names exist on R82.10 (`show-vpn-communities-meshed`/`-star`, `show-limits`, `show-gateways-and-servers`) so the best-effort pass-through is rarely exercised.
- Deeper per-column decision reasoning (time in/out-of-window NO_OP, install-on coverage matching, vpn exact-match on removal), vpn-in-amend, remove-path target-narrowing, and the mgmt_export time-as-list render — all unchanged from the round-1 deferral list.
