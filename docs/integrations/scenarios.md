# Scenarios (live-mutation engine)

The demo *control surface*. CloudGuard **polls** its Data Center objects every ~30s, so to show
dynamic policy you don't push anything — you **mutate the portal's stored inventory** and the
gateway's next scan re-resolves the affected dynamic objects and rules. This is the "change a tag →
policy updates in ~30s" moment, on demand.

- Control panel + endpoints: [`app/routers/scenarios.py`](../../app/routers/scenarios.py)
- Mutation primitives + presets: [`app/services/scenarios.py`](../../app/services/scenarios.py)
- Server-side timed runner: [`app/services/scenario_runner.py`](../../app/services/scenario_runner.py)
- UI: [`scenarios.html`](../../app/templates/scenarios.html) · timeline fragment [`scenario_timeline.html`](../../app/templates/scenario_timeline.html)

Open it under **Data Centers ▾ → Scenarios** in the nav (`/scenarios`).

## Use it

1. Pick a data center. You see its workloads (VMs / pods / instances) with their current tags.
2. **Manual edits** — per workload: `+ tag` / `− tag` (flip membership of a dynamic group), or
   **Remove** (scale-in). **Scale out** adds a workload with an IP and optional tag. Each edit flashes
   *"… — CloudGuard re-syncs within ~30s."*
3. **Run a scenario** (the stage-ready path) — pick a named preset and a pacing, click **Run**, then
   switch to SmartConsole and watch policy follow. A **live timeline** shows each step land
   (pending → done) with timestamps; **Stop** cancels the rest.
4. **Set baseline / Reset to baseline** — a snapshot is captured automatically before your first
   change, so one click restores the pre-demo inventory.

Watch it land in the [Activity log](../../app/routers/activity.py) (kind *Data Center*) as the gateway
re-scans, and in SmartConsole as the dynamic object's members change.

## Presets

Each preset expands against the DC's **current** inventory, in the provider's tag style — a bare tag
string for list-tag providers (vCenter / NSX-T / Proxmox / OpenStack) or `key=value` for Kubernetes
(labels) and Nutanix (categories):

| Preset | Steps | Demo |
|---|---|---|
| **Quarantine the first workload** | tag workload #1 `quarantine` | tag a VM → it joins the quarantine group → blocked |
| **Scale out (+3 workloads)** | add 3 workloads (unique names, free IPs in the inventory's /24), tagged `scaleout` | new workloads appear in a dynamic group as they spin up |
| **Blocklist every workload** | tag every workload `blocklist` | a staged blocklist rollout across the fleet |

A preset that can't run now (e.g. *quarantine* with no workloads) is shown but disabled. Presets are
offered only for taggable providers — **Cisco ACI** (groups resolve by IP, not tags) and the feeds
aren't wired into the engine, so they show a note instead of controls.

## How the timed runner works

The runner lives **server-side** so it keeps going after you leave the page (you *will* switch to
SmartConsole mid-demo). It's an in-memory run **per data center**, driven by an async task that:
applies a step → sleeps the chosen interval (0 = all at once, else 10/20/30s) → applies the next.
Each step commits `content` in its own short DB session, so every step is picked up by the next poll.
Starting a new run replaces the prior one; **Stop** cancels the remainder. The timeline UI polls
`GET /scenarios/{id}/run-status` every ~2s and stops once the run is done.

Pacing tip: a 20–30s interval lets each step land in a **separate** ~30s scan, so the audience sees
the policy move one step at a time rather than all at once.

Run state is intentionally **ephemeral** (process-local) — a restart drops an in-flight run, which is
fine for a seconds-to-minutes demo. The inventory mutations themselves are persisted in the DB.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/scenarios?dc=<id>` | control panel for the selected DC |
| POST | `/scenarios/{id}/mutate` | one manual edit (`add_tag` / `remove_tag` / `add_workload` / `remove_workload`) |
| POST | `/scenarios/{id}/run` | expand a preset and start the timed runner (`preset`, `interval`) |
| POST | `/scenarios/{id}/stop` | cancel the running scenario |
| GET | `/scenarios/{id}/run-status` | live timeline fragment (polled) |
| POST | `/scenarios/{id}/set-baseline` · `/reset` | capture / restore the reset target |

All are owner-gated. Mutations are deep-copied and re-assigned (no in-place edits), so a failed step
never half-writes the inventory.
