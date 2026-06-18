# DC Integration Simulator — state & roadmap

_Assessment of what's built, how good it is, and what to add to make it maximally useful for SE demos._
_Last updated: 2026-06-18._

## TL;DR

The portal is the broadest CloudGuard-Controller demo surface in one place: **8 datacenter mocks + 2
feeds + the full push side** (dynamic-layer builder → real or mock gateway), one app, **~180 tests
(177 passing)**, **live-confirmed against real R82.10 CloudGuard**. The mocks are built to each
provider's *exact* API contract (response shapes, auth, query semantics) and validated against a live
SMS — so they connect on the first/second try rather than after weeks of guessing. The gap is the part
that makes a demo *land*: **live, scriptable mutation** (the "change a tag → policy re-resolves in
~30s" moment) and the **threat-intel / auto-quarantine** story. That's the next ~20% that delivers
80% of the demo wow.

## What's integrated

| Area | Coverage | Status |
|---|---|---|
| **Datacenter mocks** | OpenStack, VMware vCenter, NSX-T, Global NSX-T, Proxmox, Cisco ACI, Kubernetes, Nutanix | **All 8 user-addressable R82.10 types built**; groups/tags resolve to member IPs |
| Live-confirmed in SmartConsole | OpenStack, vCenter, NSX-T, Proxmox, ACI, **Kubernetes**, Global NSX-T (Region) | ✅ |
| Pending | **Nutanix** (needs port 9440 open at the hosting edge — see `docs/integrations/nutanix.md`); Global NSX-T group-under-Region nesting (a CloudGuard-side limitation, documented) | ⏳ |
| **Pull feeds** | Generic Data Center (sk167210 JSON), Network Feed (flat list + JSON/JQ) | ✅ |
| **Push side** | Dynamic-layer builder → `set-dynamic-content` → **real gateway or mock Gaia**; live apply trace; history / merge-to-rulebase | ✅ |
| Gateways | CRUD, encrypted password (AES-GCM), cert-pin, real-gateway push | ✅ |
| **Diagnostics / infra** | Activity log (full request/response, redacted, per-provider filter + search), auth, Docker/Dokploy deploy, ~180 tests | ✅ |
| **Not built yet** | **IoC / threat-intel feed (M2)** · **scenario / live-mutation engine (M4)** · branding + presets + import/export (M6) | ❌ |

## How good it is

**Strengths**
- **Fidelity.** Each mock matches the exact API its CloudGuard scanner expects — response shapes, auth
  flow, query/format semantics — so integrations land fast and stay matched.
- **Full inventory that resolves to IPs** per provider (namespaces→pod IPs, ESGs→endpoints,
  categories→VMs) — the data policy actually consumes.
- **It removes the real product's demo fragility**, which is the whole value prop: no cloud
  credentials/IAM roles, no NTP-skew auth breakage, no TLS/cert dance, no scan back-off, no object
  ghosting, no silent tag-update failures.
- **The Activity log** turns "it failed" into a fixable request/response trace — a debugging tool *and*
  a demo asset.

**Gaps**
- **Static data.** Objects don't change after authoring — but the single most compelling CloudGuard
  moment is *change a tag → watch the rule re-resolve in ~30s*. Today that's a manual edit + wait.
- **No threat-intel pillar.** Without IoC feeds you can't demo Anti-Bot/AV/IPS enforcement or
  auto-quarantine.
- **No guided/repeatable scenarios or one-click reset** — every demo is manual setup, which undercuts
  the "no friction" pitch.
- **Unbranded UI** — fine internally, less polished on a customer screen-share.

## Roadmap — ranked by demo value

1. **Scenario / live-mutation engine — highest leverage.** One-click, scriptable presets that mutate
   inventory on cue so the gateway re-syncs live: *flip a VM's tag*, *grow a blocklist*, *scale-out adds
   tagged workloads*. The mock can make this instant and deterministic (no back-off, no ghosting) —
   beating a real lab at its own headline moment.
2. **IoC / threat-intel feed + the auto-quarantine scenario.** Unlocks a whole product pillar: feed →
   Anti-Bot blocks; "infect" a VM → it gets the `Check_Point.BotFound` tag → a quarantine rule isolates
   it, while a whitelisted IP stays clean (a clean negative test).
3. **One-click seed + reset + a guided "demo mode."** Pre-baked realistic environments per vertical and
   a "reset to clean" button — this *is* the friction-removal promise.
4. **Branding + templates/presets + import/export.** Customer-facing polish; shareable scenario bundles.
5. **Close the stragglers:** Nutanix port-9440 exposure (deployment step, documented); revisit Global
   NSX-T nesting only with a real multi-domain Global Manager capture.

## Killer demos this should make one-click

- **Tag flip → policy updates live** (~30s) — the headline.
- **Infect → auto-quarantine** (`Check_Point.BotFound`) + whitelist negative test.
- **Scale-out** → new tagged workloads auto-join the group/rule.
- **Threat feed** → IoC appears → Anti-Bot blocks it.

These are exactly what SEs demo and what real labs make painful — the portal can make them repeatable
and credential-free, which is the point.
