# SBT Lab Environment

Drawbridge ships a one-click **SBT Lab Environment** seed that mirrors the Check Point hands-on training
(SBT) lab's topology, so a trainee can connect CloudGuard to the mocks, import a workload, drop it into a
rule, and verify with a **real ping** through the live lab gateway.

Seed it from the dashboard: **Seed an environment → 🏛 SBT Lab Environment**. Implementation:
[`app/services/bundle.py`](../app/services/bundle.py) (`sbt_lab_bundle()`).

> **Access-automation validation moved.** This page used to be the runbook for validating the
> access-automation *write path* (the `web_api` object/rule-creation calls) against a live R82.10 SMS.
> That engine is now the separate **PolicyPilot** product, so its SBT validation runbook lives with
> PolicyPilot. Drawbridge only provides the **datacenter + feed** half of the same lab, described below.

## What the seed creates

The mocks advertise the VMs at their **real lab IPs on purpose**, so imported objects match what a ping
actually hits.

**Datacenters**

- **SBT-vCenter** (mock vCenter) — the lab VMs with bare-string tags: `Windows-Client` (10.1.1.222),
  `Windows-Server` (10.1.2.250), `AI-Ubuntu` (10.1.3.33), and `Kali-Linux` (203.0.113.5, the untrusted
  external contractor).
- **SBT-NSX-T** (mock NSX-T) — the same VMs with `scope=value` tags plus dynamic security groups:
  `SBT-Servers` (`role=server`), `Untrusted-Contractors` (`trust=untrusted`), `SBT-Zone` (`zone=sbt`).

**Feeds**

- **SBT-Network-Segments** (Generic Data Center) — the lab segments as importable objects:
  `10.1.1.0/24` (mgmt/client), `10.1.2.0/24` (server/app), `10.1.3.0/24` (DMZ/AI), and the external
  `203.0.113.0/24` contractor net.
- **SBT-Threat-Blocklist** (Network Feed) — IPs to block, including the contractor host `203.0.113.5`.
- **SBT-C2-Indicators** (IoC / Custom Intelligence) — threat indicators (the contractor host + a phishing
  domain) for the Anti-Bot / AV / IPS pillar.

## Suggested lab flow

1. Point CloudGuard at **SBT-vCenter** or **SBT-NSX-T** (see
   [docs/integrations/vcenter.md](integrations/vcenter.md) / [nsxt.md](integrations/nsxt.md)) and import a VM
   or a dynamic group.
2. Build a rule using the imported dynamic object (e.g. allow `SBT-Servers`, block `Untrusted-Contractors`)
   and install policy.
3. Verify with a **real ping** between the lab VMs through the live gateway.
4. Run a **[Scenario](integrations/scenarios.md)** on the DC (flip a tag / scale out) and watch policy
   re-resolve within ~30s.
