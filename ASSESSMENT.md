# DC Integration Simulator — state & roadmap

_Assessment of what's built, how good it is, and what to add to make it maximally useful for SE demos._
_Last updated: 2026-06-18._

## TL;DR

The portal is the broadest CloudGuard-Controller demo surface in one place: **8 datacenter mocks + 2
feeds + the full push side** (dynamic-layer builder → real or mock gateway) **+ a live-mutation
control panel**, one app, **190 tests passing**, **live-confirmed against real R82.10 CloudGuard**.
The mocks are built to each provider's *exact* API contract (response shapes, auth, query semantics)
and validated against a live SMS — so they connect on the first/second try rather than after weeks of
guessing. The **Scenarios** engine now delivers the demo-*landing* moment on cue: flip a tag / scale
out / run a timed preset → the gateway's next ~30s scan re-resolves policy, with one-click reset. The
remaining gap is the **threat-intel / auto-quarantine** pillar (IoC feed, M2) and customer-facing
**branding + import/export** (M6).

## What's integrated

| Area | Coverage | Status |
|---|---|---|
| **Datacenter mocks** | OpenStack, VMware vCenter, NSX-T, Global NSX-T, Proxmox, Cisco ACI, Kubernetes, Nutanix | **All 8 user-addressable R82.10 types built**; groups/tags resolve to member IPs |
| Live-confirmed in SmartConsole | OpenStack, vCenter, NSX-T, Proxmox, ACI, **Kubernetes**, Global NSX-T (Region) | ✅ |
| Pending | **Nutanix** (needs port 9440 open at the hosting edge — see `docs/integrations/nutanix.md`); Global NSX-T group-under-Region nesting (a CloudGuard-side limitation, documented) | ⏳ |
| **Pull feeds** | Generic Data Center (sk167210 JSON), Network Feed (flat list + JSON/JQ) | ✅ |
| **Push side** | Dynamic-layer builder → `set-dynamic-content` → **real gateway or mock Gaia**; live apply trace; history / merge-to-rulebase | ✅ |
| Gateways | CRUD, encrypted password (AES-GCM), cert-pin, real-gateway push | ✅ |
| **Live demo control** | **Scenarios** (`/scenarios`): per-workload tag flip / scale-out / remove · named presets (quarantine, scale-out, blocklist) · **server-side timed runner** with live timeline · baseline/reset | ✅ |
| **Diagnostics / infra** | Activity log (full request/response, redacted, per-provider filter + search), auth, Docker/Dokploy deploy, **190 tests** | ✅ |
| **Not built yet** | **IoC / threat-intel feed (M2)** · one-click seed + demo-mode · branding + import/export (M6) | ❌ |

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
- **No threat-intel pillar.** Without IoC feeds you can't demo Anti-Bot/AV/IPS enforcement or
  auto-quarantine.
- **Scenario engine doesn't cover everything yet.** The feeds and **Cisco ACI** (groups resolve by IP,
  not tags) aren't wired into the live-mutation engine — they show a note instead of controls.
- **No one-click seed / demo-mode** — inventory is authored by hand, then mutated live. Reset-to-baseline
  exists, but pre-baked per-vertical environments would cut setup further.
- **Unbranded UI** — fine internally, less polished on a customer screen-share.

**Resolved since last assessment**
- ~~Static data~~ — **Scenarios** now mutates inventory on cue (tag flip / scale-out / remove + timed
  presets) so the gateway re-resolves policy live, with baseline/reset for one-click cleanup.

## Roadmap — ranked by demo value

1. **IoC / threat-intel feed + the auto-quarantine scenario — highest leverage now.** Unlocks a whole
   product pillar: feed → Anti-Bot blocks; "infect" a VM → it gets the `Check_Point.BotFound` tag → a
   quarantine rule isolates it, while a whitelisted IP stays clean (a clean negative test). Pairs
   directly with the live-mutation engine (a preset can drive the "infect" step).
2. **One-click seed + a guided "demo mode."** Pre-baked realistic environments per vertical on top of the
   existing reset-to-baseline — this *is* the friction-removal promise.
3. **Branding + import/export.** Customer-facing polish; shareable scenario/environment bundles.
4. **Close the stragglers:** Nutanix port-9440 exposure (deployment step, documented); revisit Global
   NSX-T nesting only with a real multi-domain Global Manager capture; wire feeds/ACI into Scenarios.

✅ **Done:** scenario / live-mutation engine — per-workload mutation, named presets, server-side timed
runner with live timeline, baseline/reset (`docs/integrations/scenarios.md`).

## Killer demos this should make one-click

- ✅ **Tag flip → policy updates live** (~30s) — the headline. *(Scenarios: per-row flip + quarantine/blocklist presets.)*
- **Infect → auto-quarantine** (`Check_Point.BotFound`) + whitelist negative test. *(needs the IoC feed, M2.)*
- ✅ **Scale-out** → new tagged workloads auto-join the group/rule. *(Scenarios: scale-out preset.)*
- **Threat feed** → IoC appears → Anti-Bot blocks it. *(needs the IoC feed, M2.)*

These are exactly what SEs demo and what real labs make painful — the portal can make them repeatable
and credential-free, which is the point.
