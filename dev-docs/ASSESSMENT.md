# DC Integration Simulator — state & roadmap

_Assessment of what's built, how good it is, and what to add to make it maximally useful for SE demos._
_Last updated: 2026-06-28._

> **Since this assessment: the push / policy side split out.** The Dynamic-Layer builder, Management-API
> export, Gaia export, and Access-Automation (ticket → rule) are now the separate **PolicyPilot** product.
> Drawbridge is the poll-side simulator (datacenter mocks + feeds) plus the reverse SIEM sink. Where this
> doc says "full push side / dynamic-layer builder / 900+ tests", read it as historical — the current
> suite is ~251 tests covering what remains here.

## TL;DR

The portal is the broadest CloudGuard / Quantum integration demo surface in one place: **8 datacenter
mocks + 3 feeds + the full push side** (dynamic-layer builder → real or mock gateway) **+ a SIEM
receiver** (Log Exporter sink) **+ a live-mutation control panel**, one app, **900+ tests passing**,
**live-confirmed against real R82.10 CloudGuard**. The mocks are built to each provider's *exact* API
contract (response shapes, auth, query semantics) and validated against a live SMS — so they connect
on the first/second try rather than after weeks of guessing. The **Scenarios** engine delivers the
demo-*landing* moment on cue (flip a tag / scale out / run a timed preset → the gateway's next ~30s
scan re-resolves policy), the **IoC feed** adds the threat-intel pillar (Anti-Bot / AV / IPS), and
**one-click seed + PoV bundle export/import** removes setup friction. The remaining headline gap is a
one-click **auto-quarantine** demo; customer-facing **branding** is the main polish item left.

## What's integrated

| Area | Coverage | Status |
|---|---|---|
| **Datacenter mocks** | OpenStack, VMware vCenter, NSX-T, Global NSX-T, Proxmox, Cisco ACI, Kubernetes, Nutanix | **All 8 user-addressable R82.10 types built**; groups/tags resolve to member IPs; full edit + inline field edit |
| Live-confirmed in SmartConsole | OpenStack, vCenter, NSX-T, Proxmox, ACI, Kubernetes, Global NSX-T (Region) | ✅ |
| Pending live-confirm | **Nutanix** (port 9440 now published by compose + documented for Dokploy); Global NSX-T group-under-Region nesting (a CloudGuard-side limitation, documented) | ⏳ |
| **Pull feeds** | Generic Data Center (sk167210 JSON), Network Feed (flat list + JSON/JQ), **IoC / Custom Intelligence** — CSV / STIX 1.x / Custom CSV / Snort | ✅ |
| **Push side** | Dynamic-layer builder → `set-dynamic-content` → **real gateway or mock Gaia**; live apply trace; history / merge-to-rulebase; inline rename | ✅ |
| **SIEM receiver** *(reverse)* | Log Exporter sink — CEF / LEEF / JSON / syslog over TCP+UDP, parsed + live viewer (`/siem`), "send test log" | ✅ |
| Gateways & DC creds | **AES-256-GCM encrypted at rest**; **trust-on-first-use** cert pinning (TLS never disabled); real-gateway push | ✅ |
| **Live demo control** | **Scenarios** (`/scenarios`): tag flip / scale-out / remove · presets (quarantine, scale-out, blocklist) · **timed runner** + live timeline · per-preset **talk-tracks** · baseline/reset | ✅ |
| **PoV enablement** | **One-click seed** (full demo env + a running scenario) · **export/import** a portable bundle (no secrets) | ✅ |
| **Diagnostics / infra** | Activity log (full request/response, redacted, per-provider filter + search), auth, Docker/Dokploy deploy, **900+ tests** | ✅ |
| **Not built yet** | one-click **auto-quarantine** demo (IoC → BotFound → quarantine) · customer-facing **branding/logo** · feeds not yet wired into Scenarios | ❌ |

## How good it is

**Strengths**
- **Fidelity.** Each mock matches the exact API its CloudGuard scanner expects — response shapes, auth
  flow, query/format semantics — so integrations land fast and stay matched.
- **Full inventory that resolves to IPs** per provider (namespaces→pod IPs, ESGs→endpoints,
  categories→VMs) — the data policy actually consumes.
- **It removes the real product's demo fragility:** no cloud credentials/IAM roles, no NTP-skew auth
  breakage, no TLS/cert dance, no scan back-off, no object ghosting, no silent tag-update failures.
- **One-click seed + bundle export/import** make a demo environment reproducible and shareable across
  SEs / per customer — credential-free.
- **The Activity log** turns "it failed" into a fixable request/response trace — a debugging tool *and*
  a demo asset.

**Gaps**
- **Auto-quarantine isn't one-click yet.** The IoC feed and the live-mutation engine both exist, but
  the *combined* loop — "infect" a VM → it gets the `Check_Point.BotFound` tag → a quarantine rule
  isolates it, while a whitelisted IP stays clean — isn't wired into a single preset/scenario.
- **Scenario engine doesn't cover the feeds yet.** The pull feeds (incl. IoC) and **Cisco ACI** (groups
  resolve by IP, not tags) aren't wired into the live-mutation engine — so you can't yet *grow a
  blocklist live* from the Scenarios panel; you edit the feed instead.
- **Unbranded UI** — a logo / white-label is still pending.

**Resolved since last assessment**
- ~~No one-click seed / demo-mode~~ — **Seed demo environment** + **PoV bundle export/import** shipped.
- ~~No SIEM / logging story~~ — the **SIEM receiver** ingests Log Exporter output live (`docs/integrations/siem.md`).
- ~~No demo guidance~~ — scenario **talk-tracks** (story + SmartConsole steps) per preset.
- ~~Create-or-delete only~~ — full **edit + inline field edit** for feeds, datacenters, and dynamic layers.

## Roadmap — ranked by demo value

1. **One-click auto-quarantine — highest leverage now.** A preset that "infects" a workload (drops the
   `Check_Point.BotFound` tag, or grows the IoC feed) so a quarantine rule isolates it on the next scan,
   with a whitelisted IP staying clean (a clean negative test).
2. **Wire the feeds into Scenarios.** Let the live-mutation panel grow/shrink the IoC + network feeds on
   cue, so "threat feed updates → Anti-Bot blocks it" is a one-click, timed step like the DC mutations.
3. **Branding / white-label.** Logo, favicon, login screen — customer-facing polish for screen-shares.
4. **Identity Awareness simulator** *(next big integration)* — push user→IP→group mappings to the
   gateway's Identity Web API (and a mock endpoint), with login/logout/role-move scenarios. Identity is
   the largest remaining axis and reuses the existing push + mock + scenario machinery.
5. **Close the stragglers:** confirm Nutanix live (9440 published); revisit Global NSX-T nesting only
   with a real multi-domain Global Manager capture; wire ACI into Scenarios.

## Killer demos this makes one-click

- ✅ **Tag flip → policy updates live** (~30s) — the headline. *(Scenarios: per-row flip + presets.)*
- ✅ **Scale-out** → new tagged workloads auto-join the group/rule. *(Scenarios: scale-out preset.)*
- ✅ **Threat feed** → IoC appears → Anti-Bot blocks it. *(IoC feed; growing it live from Scenarios is next.)*
- ✅ **Gateway logs reach the SIEM** → Log Exporter → `/siem` shows them parsed, live.
- **Infect → auto-quarantine** (`Check_Point.BotFound`) + whitelist negative test. *(both halves exist; needs the combined preset — roadmap #1.)*

These are exactly what SEs demo and what real labs make painful — the portal makes them repeatable and
credential-free, which is the point.
