# Changelog

All notable changes to **Drawbridge** are documented here. This project follows
[Semantic Versioning](https://semver.org/).

## 1.0.0 — 2026-06-28

First general release for SEs and customers. Validated against a live Check Point **R82.10** Management
Server.

> **Scope note.** The policy-automation side of the earlier monolith — Dynamic Layers, Management-API
> export, Gaia config export, and Access Automation (ticket → rule) with its MCP server and REST API —
> has been split into its own product, **PolicyPilot**. Drawbridge is now purely the integration
> simulator: the systems Check Point *polls* plus the *reverse* SIEM sink. Feed Drawbridge's data into a
> real Management Server running PolicyPilot.

### Simulate the systems Check Point integrates with (poll side)
- **Data center mocks**, each built to the provider's exact API contract: OpenStack (Keystone/Nova/Neutron),
  VMware vCenter (vSphere SOAP + REST), VMware NSX-T (Local Manager) and **Global NSX-T** (Federation),
  Proxmox VE, Cisco ACI (APIC XML), Kubernetes (kube-apiserver), and Nutanix Prism (v3 + v4).
- **Feeds**: Generic Data Center (sk167210), Network Feed (flat list / JSON + JQ), and IoC / Custom
  Intelligence (CSV / STIX 1.x / Custom CSV / Snort).
- **Test Connection** and **Live polls** show objects syncing in the provider's own format.

### Reverse (Check Point sends to the portal)
- **SIEM receiver** — a Log Exporter sink that auto-detects CEF / LEEF / JSON / key=value / syslog over
  TCP+UDP and shows logs arriving live.

### Live-demo tooling
- **Scenarios** with SE talk-tracks, timed preset runs, and baseline/reset.
- **One-click seed** of a realistic environment (feeds + datacenters, with a live scenario auto-started);
  portable **export/import** bundles (never carry credentials).
- **Activity log** — every request/response, redacted, filterable.

### Security
- All datacenter TLS **always verified** (trust-on-first-use cert pinning for self-signed lab boxes).
- Saved datacenter credentials **AES-256-GCM encrypted at rest**.
- Defensive HTTP response headers (anti-clickjacking, nosniff, Referrer-Policy, HSTS).
- Parameterized queries throughout; portal logins use PBKDF2; secrets never logged.
- Reproducible build (pinned dependencies, non-root container, healthcheck).
