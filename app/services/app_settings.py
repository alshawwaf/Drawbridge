"""User-tunable runtime behaviour for how the portal talks to a Check Point SMS.

Real production integrations do NOT log in and re-pull the whole policy on every request — Check Point
throttles remote API logins (3 per admin, per domain, per 60s in R81+) and caps concurrent sessions
(100). So the portal (a) reuses a shared read-only session for reads and (b) caches the pulled policy,
refreshing only when a new revision is published. Every knob here is editable from the **Settings**
page so an admin controls the behaviour from the portal — no code or env edits.

Stored in the ``AppState`` key/value table so a change from any worker/replica is shared; a small
in-process cache keeps these off the hot path (mirrors the SIEM pause toggle)."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Union

from ..db import SessionLocal
from ..models import AppState
from . import crypto

_log = logging.getLogger("dcsim.settings")
_PREFIX = "set:"            # AppState key namespace, so settings never collide with other state
_CACHE_TTL = 2.0
_cache: dict = {"at": -1e9, "vals": {}}

# Secrets ("secret" kind) are stored ENCRYPTED at rest (AES-256-GCM, org policy) and never enter the
# general value map / settings render path — they're read out-of-band via get_secret(). A short cache
# keeps the auth hot-path (e.g. the MCP bearer check) off the DB without making rotation feel laggy.
_SECRET_TTL = 5.0
_secret_cache: dict = {}    # key -> (monotonic_at, plaintext)


def _secret_info(key: str) -> bytes:
    return b"dcsim-setting:" + key.encode()


@dataclass(frozen=True)
class Setting:
    key: str
    kind: str                       # "bool" | "int" | "str" | "secret" | "choice"
    default: Union[bool, int, str]
    label: str
    help: str
    group: str = "Management API"
    min: int = 0
    max: int = 0                    # for "str": max length (0 → default cap)
    generate: bool = False          # secret-only: offer a "Generate" button (a strong random token)
    choices: tuple = ()             # choice-only: ((value, label), …) rendered as a <select>; value validated


SETTINGS: list[Setting] = [
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

    # --- Portal --------------------------------------------------------------------------------------
    Setting("base_url", "str", "",
            "Public base URL",
            "The public URL this portal is reached at (e.g. https://dcsim.example.com), stamped into the "
            "feed / GDC / Keystone / gaia_api URLs shown to the SE and the MCP/webhook endpoints on the "
            "guide pages. Set it here to change the displayed URLs with no redeploy. Leave blank to use "
            "DCSIM_BASE_URL (or http://localhost:8000 in dev). NOTE: the session-cookie 'Secure' flag is "
            "still decided at startup from DCSIM_BASE_URL's scheme, so for HTTPS cookie hardening set the "
            "env var too.",
            group="Portal", max=200),
]

_BY_KEY = {s.key: s for s in SETTINGS}


def defaults() -> dict:
    # Secrets are handled out-of-band (get_secret) and never enter the general value map / render path.
    return {s.key: s.default for s in SETTINGS if s.kind != "secret"}


def _coerce(s: Setting, raw):
    if s.kind == "bool":
        return str(raw) == "1"
    if s.kind == "choice":
        v = "" if raw is None else str(raw)
        return v if v in {c[0] for c in s.choices} else s.default   # unknown value -> default (fail safe)
    if s.kind in ("str", "text"):                                   # text = multiline (rendered as a textarea)
        cap = s.max or (4000 if s.kind == "text" else 200)
        return ("" if raw is None else str(raw))[:cap]
    try:
        v = int(raw)
    except (TypeError, ValueError):
        return s.default
    return max(s.min, min(s.max, v))


def _to_text(s: Setting, value) -> str:
    if s.kind == "bool":
        truthy = value is True or str(value).strip().lower() in ("1", "true", "on", "yes")
        return "1" if truthy else "0"
    if s.kind in ("str", "choice", "text"):
        return _coerce(s, value)
    return str(_coerce(s, str(value)))


def all_values(fresh: bool = False) -> dict:
    """The full, validated settings map (defaults overlaid with any stored values). Cached ~2s."""
    now = time.monotonic()
    if not fresh and (now - _cache["at"]) <= _CACHE_TTL and _cache["vals"]:
        return dict(_cache["vals"])
    vals = defaults()
    try:
        db = SessionLocal()
        try:
            for s in SETTINGS:
                if s.kind == "secret":        # never read/return a secret here (would leak into render)
                    continue
                row = db.get(AppState, _PREFIX + s.key)
                if row is not None:
                    vals[s.key] = _coerce(s, row.value)
        finally:
            db.close()
    except Exception:  # noqa: BLE001 — a DB read failure degrades to defaults (callers add env fallback), never 500
        _log.warning("app_settings.all_values: DB read failed; serving defaults")
        return defaults()
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
            if s.kind == "secret" or s.key not in values:
                continue                      # secrets go through set_secret/clear_secret, never here
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


# --- Secrets (encrypted at rest) ---------------------------------------------------------------------

def secret_settings() -> list[Setting]:
    return [s for s in SETTINGS if s.kind == "secret"]


def secret_available() -> bool:
    """True when secrets can actually be stored (AES-256 key material is configured). When False the UI
    must tell the admin to set DCSIM_ENCRYPTION_KEY / DCSIM_SESSION_SECRET and fall back to env vars."""
    return crypto.available()


def get_secret(key: str) -> str:
    """The decrypted plaintext of a stored secret, or "" if unset/undecryptable. Short-TTL cached so an
    auth hot-path (the MCP bearer check) doesn't hit the DB per request, while rotation still lands fast."""
    now = time.monotonic()
    hit = _secret_cache.get(key)
    if hit is not None and (now - hit[0]) <= _SECRET_TTL:
        return hit[1]
    plain = ""
    try:
        db = SessionLocal()
        try:
            row = db.get(AppState, _PREFIX + key)
            if row is not None and row.value:
                plain = crypto.decrypt(row.value, _secret_info(key)) or ""
                if not plain:
                    # a row exists but won't decrypt — wrong/rotated key, not "unset". Surface it (key
                    # name only, never the value) so a key/session-secret change doesn't silently orphan
                    # the secret and revert auth to the env fallback with no signal.
                    _log.warning("app_settings.get_secret(%s): stored value did not decrypt "
                                 "(encryption key changed?); falling back to env/disabled", key)
        finally:
            db.close()
    except Exception:  # noqa: BLE001 — a DB hiccup on the auth path must fail safe (env fallback), not 500
        _log.warning("app_settings.get_secret(%s): read failed; falling back to env/disabled", key)
        return ""
    _secret_cache[key] = (now, plain)
    return plain


def secret_is_set(key: str) -> bool:
    """True when a usable (decryptable, non-empty) secret is stored for this key."""
    return bool(get_secret(key))


def secret_status() -> dict:
    """{key: bool is_set} for every secret setting — for the UI status pills (never the value)."""
    return {s.key: secret_is_set(s.key) for s in secret_settings()}


def set_secret(key: str, plaintext: str) -> None:
    """Encrypt + store a secret. Empty plaintext is a no-op (the UI submits blank to mean 'keep current').
    Raises RuntimeError when encryption is unavailable — we never store a credential in cleartext."""
    if not plaintext:
        return
    token = crypto.encrypt(plaintext, _secret_info(key))    # raises if crypto unavailable
    db = SessionLocal()
    try:
        row = db.get(AppState, _PREFIX + key)
        if row is None:
            db.add(AppState(key=_PREFIX + key, value=token))
        else:
            row.value = token
        db.commit()
    finally:
        db.close()
    _secret_cache.pop(key, None)


def clear_secret(key: str) -> None:
    """Remove a stored secret (the endpoint/integration falls back to its env var, or off)."""
    db = SessionLocal()
    try:
        row = db.get(AppState, _PREFIX + key)
        if row is not None:
            db.delete(row)
            db.commit()
    finally:
        db.close()
    _secret_cache.pop(key, None)


# --- Runtime resolution with env fallback ------------------------------------------------------------
# A portal Setting takes precedence; a matching DCSIM_ env var is the fallback (so existing env-based
# deployments keep working and a value can be set/rotated from the UI without a redeploy).

def get_or_env(key: str, env_value) -> str:
    """A non-secret string setting if set, else the supplied env value (e.g. get_settings().webhook_server_ids)."""
    v = get(key)
    return v if v not in (None, "") else (env_value or "")


def get_secret_or_env(key: str, env_value) -> str:
    """A stored secret if set, else the supplied env value (the env var is the fallback)."""
    return get_secret(key) or (env_value or "")


def base_url() -> str:
    """The portal's public base URL: the 'base_url' Setting if set, else DCSIM_BASE_URL (default
    http://localhost:8000). Single resolution point for every emitted feed/endpoint URL."""
    from ..config import get_settings
    return get_or_env("base_url", get_settings().base_url) or "http://localhost:8000"
