"""User-tunable runtime behaviour for how the portal talks to a Check Point SMS.

Real production integrations do NOT log in and re-pull the whole policy on every request — Check Point
throttles remote API logins (3 per admin, per domain, per 60s in R81+) and caps concurrent sessions
(100). So the portal (a) reuses a shared read-only session for reads and (b) caches the pulled policy,
refreshing only when a new revision is published. Every knob here is editable from the **Settings**
page so an admin controls the behaviour from the portal — no code or env edits.

Stored in the ``AppState`` key/value table so a change from any worker/replica is shared; a small
in-process cache keeps these off the hot path (mirrors the SIEM pause toggle)."""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Union

from ..db import SessionLocal
from ..models import AppState

_PREFIX = "set:"            # AppState key namespace, so settings never collide with other state
_CACHE_TTL = 2.0
_cache: dict = {"at": -1e9, "vals": {}}


@dataclass(frozen=True)
class Setting:
    key: str
    kind: str                       # "bool" | "int" | "str"
    default: Union[bool, int, str]
    label: str
    help: str
    group: str = "Management API"
    min: int = 0
    max: int = 0                    # for "str": max length (0 → default cap)


SETTINGS: list[Setting] = [
    Setting("mgmt_session_reuse", "bool", True,
            "Reuse a shared session for reads",
            "Log in once and reuse a read-only session for all reads (layers, rulebase, export, "
            "preview) instead of logging in on every request. Check Point throttles remote logins to 3 "
            "per minute, so this is what prevents the 'too many login requests' failures. Strongly "
            "recommended — turn off only to debug."),
    Setting("mgmt_session_timeout", "int", 3600,
            "Read session timeout (seconds)",
            "Idle timeout for the shared read session. Check Point allows 60–3600s; the portal "
            "keepalives it so it survives a whole demo.", min=60, max=3600),
    Setting("mgmt_keepalive", "bool", True,
            "Keep the read session alive",
            "Send a lightweight keepalive before reusing an idle session so it never expires mid-demo "
            "(keepalive does not count against the login throttle)."),
    Setting("mgmt_policy_cache", "bool", True,
            "Cache the pulled policy",
            "Reuse the parsed rulebase while the policy is unchanged instead of pulling the whole "
            "rulebase + objects every time. Change is detected by the latest published revision, so the "
            "portal re-pulls only after someone publishes."),
    Setting("mgmt_cache_revalidate", "int", 30,
            "Revalidate interval (seconds)",
            "Minimum time between change-checks. Within this window the cached policy is served without "
            "even asking the SMS whether it changed (0 = check every request).", min=0, max=3600),
    Setting("mgmt_cache_max_age", "int", 900,
            "Force full refresh after (seconds)",
            "Re-pull the whole policy at least this often regardless of revision — a safety net for "
            "changes made outside the published-session signal.", min=30, max=86400),
    Setting("mgmt_write_fresh", "bool", True,
            "Always pull fresh before applying",
            "Before committing a change (apply / publish), re-pull the live policy so the decision is "
            "never based on a cached rulebase. Recommended."),
    Setting("mgmt_write_session_timeout", "int", 300,
            "Write session idle timeout (seconds)",
            "Idle timeout for the read-write session used by an apply/publish. An apply runs in seconds, "
            "so a short value means a lock left by an interrupted apply (a 'Locked for editing' error) "
            "clears quickly instead of lingering ~10 minutes. 60–3600.", min=60, max=3600),

    # --- Storage & retention -------------------------------------------------------------------------
    # The two high-volume tables (the Activity log and the built-in SIEM receiver) are bounded so a
    # long-running demo — a Data Center importing on a schedule, or Log Exporter streaming for days —
    # can never fill the disk. A background sweep (started in main.lifespan) enforces these caps.
    Setting("activity_max_records", "int", 5000,
            "Activity log — keep newest N",
            "Hard cap on the Activity log table: older entries are trimmed (cheap indexed delete) so the "
            "database can't grow without bound while integrations run. 0 = unlimited (not recommended in "
            "production).", group="Storage & retention", min=0, max=2_000_000),
    Setting("activity_max_age_days", "int", 0,
            "Activity log — also delete older than (days)",
            "Additionally drop Activity log entries older than this many days, regardless of count. "
            "0 = keep by record count only.", group="Storage & retention", min=0, max=3650),
    Setting("siem_max_records", "int", 2000,
            "SIEM receiver — keep newest N",
            "Hard cap on the built-in SIEM (Log Exporter) table so a flooding gateway can't fill the disk "
            "— it's a live demo viewer, not a log archive. 0 = unlimited (not recommended).",
            group="Storage & retention", min=0, max=2_000_000),
    Setting("retention_sweep_min", "int", 5,
            "Housekeeping interval (minutes)",
            "How often the background pass enforces the caps above. Trimming is a cheap indexed range "
            "delete that fires only when a table is over cap, so a few minutes is plenty.",
            group="Storage & retention", min=1, max=1440),
    Setting("retention_notify", "bool", True,
            "Notify when records are trimmed",
            "Post a notification (the header bell) when a housekeeping sweep trims records, so retention "
            "is never silent. Throttled to at most once an hour.", group="Storage & retention"),

    # --- Access automation — naming of auto-created objects ------------------------------------------
    # When the engine has to CREATE an object for a request, it names it from these templates. Defaults
    # reproduce the built-in h-/n- scheme; clear a field to fall back to the default.
    Setting("name_host", "str", "h-{ip_dashed}",
            "Host object name",
            "Name for a host object auto-created for a single-address (/32) endpoint. Placeholders: "
            "{ip} (e.g. 1.2.3.4), {ip_dashed} (1-2-3-4).", group="Access automation", max=100),
    Setting("name_network", "str", "n-{ip_dashed}-{prefix}",
            "Network object name",
            "Name for a network object auto-created for a CIDR endpoint. Placeholders: {ip}, {ip_dashed}, "
            "{prefix} (the mask length, e.g. 24).", group="Access automation", max=100),
    Setting("name_service", "str", "{PROTO}-{port}",
            "Service object name",
            "Name for a TCP/UDP service auto-created for a requested port. Placeholders: {proto} (tcp), "
            "{PROTO} (TCP), {port}.", group="Access automation", max=100),
    Setting("name_rule", "str", "TKT-{ticket}",
            "New rule name",
            "Name for a rule the engine creates. Placeholder: {ticket}. With no ticket id (and a "
            "ticket-based template) the rule is left unnamed and Check Point auto-names it.",
            group="Access automation", max=120),
]

_BY_KEY = {s.key: s for s in SETTINGS}


def defaults() -> dict:
    return {s.key: s.default for s in SETTINGS}


def _coerce(s: Setting, raw):
    if s.kind == "bool":
        return str(raw) == "1"
    if s.kind == "str":
        return ("" if raw is None else str(raw))[: (s.max or 200)]
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return s.default
    return max(s.min, min(s.max, v))


def _to_text(s: Setting, value) -> str:
    if s.kind == "bool":
        truthy = value is True or str(value).strip().lower() in ("1", "true", "on", "yes")
        return "1" if truthy else "0"
    if s.kind == "str":
        return _coerce(s, value)
    return str(_coerce(s, str(value)))


def all_values(fresh: bool = False) -> dict:
    """The full, validated settings map (defaults overlaid with any stored values). Cached ~2s."""
    now = time.monotonic()
    if not fresh and (now - _cache["at"]) <= _CACHE_TTL and _cache["vals"]:
        return dict(_cache["vals"])
    vals = defaults()
    db = SessionLocal()
    try:
        for s in SETTINGS:
            row = db.get(AppState, _PREFIX + s.key)
            if row is not None:
                vals[s.key] = _coerce(s, row.value)
    finally:
        db.close()
    _cache.update(at=now, vals=vals)
    return dict(vals)


def get(key: str):
    """One validated value (falls back to the default). Cheap — reads the ~2s cache."""
    return all_values().get(key, _BY_KEY[key].default if key in _BY_KEY else None)


def save(values: dict) -> dict:
    """Persist the provided keys (unknown keys ignored; values validated + clamped). Returns the new
    full value map and busts the cache so the change takes effect immediately across the process."""
    db = SessionLocal()
    try:
        for s in SETTINGS:
            if s.key not in values:
                continue
            text = _to_text(s, values[s.key])
            row = db.get(AppState, _PREFIX + s.key)
            if row is None:
                db.add(AppState(key=_PREFIX + s.key, value=text))
            else:
                row.value = text
        db.commit()
    finally:
        db.close()
    _cache["at"] = -1e9
    return all_values(fresh=True)
