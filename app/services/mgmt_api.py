"""Client for the Check Point Management API (``web_api``) — the real-SMS side of the policy
viewer/editor/exporter.

A session does ``login`` (with an optional MDS ``domain``) → carries the ``sid`` on every call →
``publish``/``discard`` for writes → ``logout``. TLS verification is **always on**: against a pinned
certificate (trust-on-first-use, like saved gateways) when one is set, otherwise system trust. Never a
skip-verify path. Each call is recorded on ``session.trace`` so the UI can show exactly what ran.
"""
from __future__ import annotations

import ssl
import time

import httpx

from .gaia_client import ensure_pinned  # noqa: F401 — re-exported; routers pin a server's cert the same way


class MgmtError(Exception):
    """A web_api login or command failed — carries a clean, user-facing message."""


def _pinned_ssl_context(cert_pem: str) -> ssl.SSLContext:
    """Trust ONLY the pinned certificate. Verification stays on (CERT_REQUIRED, TLS 1.2+); hostname
    matching is off because management certs are often issued for a name the lab reaches it by — the
    operator-reviewed pin is the identity check. (Same policy-safe approach as the gateway apply.)"""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    ctx.load_verify_locations(cadata=cert_pem)
    return ctx


def _verify_for(server):
    pem = (getattr(server, "cert_pem", "") or "").strip()
    return _pinned_ssl_context(pem) if pem else True


class MgmtSession:
    """One authenticated web_api session. Use as a context manager so logout + close always run::

        with MgmtSession(server, secret) as s:
            layers = s.list_access_layers()
    """

    def __init__(self, server, secret: str, timeout: float = 30.0):
        self.server = server
        self._secret = secret
        self.base = f"https://{server.host}:{server.port}/web_api"
        self._client = httpx.Client(verify=_verify_for(server), timeout=timeout)
        self.sid: str | None = None
        self.login_info: dict = {}
        self.trace: list[dict] = []

    # --- lifecycle ---------------------------------------------------------------------------
    def __enter__(self) -> "MgmtSession":
        self.login()
        return self

    def __exit__(self, *exc) -> None:
        try:
            self.logout()
        finally:
            self._client.close()

    def login(self) -> dict:
        payload: dict = {"user": self.server.username, "password": self._secret}
        if (self.server.domain or "").strip():
            payload["domain"] = self.server.domain.strip()   # MDS/CMA target; omitted for a single SMS
        try:
            t = time.perf_counter()
            r = self._client.post(f"{self.base}/login", json=payload)
        except (httpx.ConnectError, ssl.SSLError, httpx.ConnectTimeout) as exc:
            raise MgmtError(f"Could not reach {self.server.host}:{self.server.port} over TLS — {exc}. "
                            "Check the host/port, the firewall, and (for a self-signed cert) the pinned "
                            "cert / auto-trust.") from exc
        self._record("login", {"user": self.server.username, "password": "***",
                               **({"domain": self.server.domain} if self.server.domain else {})}, r, t)
        if r.status_code != 200:
            raise MgmtError(_login_error(r))
        self.login_info = _safe_json(r)
        self.sid = self.login_info.get("sid")
        if not self.sid:
            raise MgmtError("Login returned no session id (sid).")
        return self.login_info

    def logout(self) -> None:
        if not self.sid:
            return
        try:
            self.call("logout")
        except Exception:  # noqa: BLE001 — best-effort; the session expires server-side anyway
            pass
        self.sid = None

    # --- calls -------------------------------------------------------------------------------
    def call(self, command: str, payload: dict | None = None) -> dict:
        if not self.sid:
            raise MgmtError("Not logged in.")
        t = time.perf_counter()
        r = self._client.post(f"{self.base}/{command}", json=payload or {},
                              headers={"X-chkp-sid": self.sid})
        self._record(command, payload or {}, r, t)
        data = _safe_json(r)
        if r.status_code != 200:
            raise MgmtError(data.get("message") or data.get("errors")
                            or f"{command} failed (HTTP {r.status_code}).")
        return data

    def call_paged(self, command: str, payload: dict | None = None, *,
                   key: str = "objects", limit: int = 500) -> list[dict]:
        """Walk CP's offset/total pagination for a show-* list command, returning all items."""
        base = dict(payload or {})
        out: list[dict] = []
        offset = 0
        while True:
            page = self.call(command, {**base, "limit": limit, "offset": offset, "details-level": "full"})
            items = page.get(key) or []
            out.extend(items)
            total = page.get("total", len(out))
            offset += len(items)
            if not items or offset >= total:
                return out

    def publish(self) -> dict:
        return self.call("publish")

    def discard(self) -> dict:
        return self.call("discard")

    # --- convenience reads -------------------------------------------------------------------
    def show_domains(self) -> list[dict]:
        try:
            return self.call("show-domains", {"limit": 200}).get("objects", [])
        except MgmtError:
            return []   # not an MDS — single SMS has no domains

    def list_access_layers(self) -> list[dict]:
        # show-access-layers returns the list under "access-layers" — NOT the usual "objects" key.
        return self.call_paged("show-access-layers", key="access-layers")

    def _record(self, command: str, payload: dict, resp, t0: float) -> None:
        self.trace.append({"command": command, "params": payload, "status": resp.status_code,
                           "ms": round((time.perf_counter() - t0) * 1000)})


def _safe_json(resp) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {"objects": data} if isinstance(data, list) else {}
    except Exception:  # noqa: BLE001
        return {}


def _login_error(resp) -> str:
    msg = ""
    try:
        body = resp.json() or {}
        msg = body.get("message") or body.get("errors") or body.get("error") or ""
    except Exception:  # noqa: BLE001
        msg = ""
    if resp.status_code in (401, 403):
        return (f"Management login failed ({resp.status_code}): the server rejected the credentials"
                + (f" — {msg}" if msg else "")
                + ". For MDS, also check the target domain.")
    return f"Management login failed (HTTP {resp.status_code})." + (f" {msg}" if msg else "")


# --- rulebase pull + structuring (the read-only viewer) -------------------------------------

def _obj_names(cell, objdict: dict) -> list[str]:
    """Resolve a rule cell (list of object UIDs, or inline object dicts) to display names."""
    out: list[str] = []
    for it in cell or []:
        if isinstance(it, str):
            out.append((objdict.get(it) or {}).get("name") or it)
        elif isinstance(it, dict):
            out.append(it.get("name") or (objdict.get(it.get("uid")) or {}).get("name") or it.get("uid", ""))
    return out


def _one_name(val, objdict: dict) -> str:
    """Resolve a single-valued cell (action / track type) to a display name."""
    if isinstance(val, str):
        return (objdict.get(val) or {}).get("name") or val
    if isinstance(val, dict):
        return val.get("name") or (objdict.get(val.get("uid")) or {}).get("name") or val.get("uid", "")
    return ""


def _structure_rule(rule: dict, objdict: dict) -> dict:
    return {
        "kind": "rule",
        "number": rule.get("rule-number"),
        "name": rule.get("name", ""),
        "enabled": rule.get("enabled", True),
        "source": _obj_names(rule.get("source"), objdict),
        "source_negate": bool(rule.get("source-negate")),
        "destination": _obj_names(rule.get("destination"), objdict),
        "destination_negate": bool(rule.get("destination-negate")),
        "vpn": _obj_names(rule.get("vpn"), objdict),
        "service": _obj_names(rule.get("service"), objdict),
        "service_negate": bool(rule.get("service-negate")),
        "action": _one_name(rule.get("action"), objdict),
        "track": _one_name((rule.get("track") or {}).get("type"), objdict),
        "install_on": _obj_names(rule.get("install-on"), objdict),
        "comments": rule.get("comments", ""),
    }


def _structure_rulebase(items: list[dict], objdict: dict) -> list[dict]:
    """Flatten the rulebase into rows the UI renders: section headers + rules (cells resolved to
    names). Unknown item types pass through flagged, mirroring CP's tool — never break on a new type."""
    out: list[dict] = []
    for it in items or []:
        t = it.get("type")
        if t == "access-section":
            out.append({"kind": "section", "name": it.get("name", "")})
            out.extend(_structure_rule(r, objdict) for r in (it.get("rulebase") or []))
        elif t == "access-rule":
            out.append(_structure_rule(it, objdict))
        else:
            out.append({"kind": "other", "type": t or "unknown", "name": it.get("name", "")})
    return out


def pull_layers(server, secret: str) -> dict:
    with MgmtSession(server, secret) as s:
        layers = s.list_access_layers()
        return {"layers": [{"name": l.get("name"), "uid": l.get("uid")} for l in layers], "trace": s.trace}


def pull_rulebase(server, secret: str, layer: str, max_rules: int = 5000) -> dict:
    """Pull a layer's access rulebase with its object dictionary, paginating, and resolve every cell
    to names. Returns {layer, rows, total, shown, trace}."""
    with MgmtSession(server, secret) as s:
        items: list[dict] = []
        objdict: dict = {}
        total, offset = 0, 0
        while offset < max_rules:
            page = s.call("show-access-rulebase",
                          {"name": layer, "limit": 100, "offset": offset, "use-object-dictionary": True})
            for o in page.get("objects-dictionary", []):
                if o.get("uid"):
                    objdict[o["uid"]] = o
            batch = page.get("rulebase", [])
            items.extend(batch)
            total = page.get("total", total)
            to = page.get("to", 0)
            if not batch or to >= total or to <= offset:
                break
            offset = to
        rows = _structure_rulebase(items, objdict)
        shown = sum(1 for r in rows if r["kind"] == "rule")
        return {"layer": layer, "rows": rows, "total": total, "shown": shown, "trace": s.trace}


def _collect_export_objects(objdict: dict) -> dict:
    """Group the referenced objects by type for export, skipping predefined ones and recursing into
    group members (which arrive as full nested objects at details-level full). Keyed by CP type."""
    from . import mgmt_export   # local import avoids a cycle (mgmt_export has no api dependency)

    by_type: dict[str, list] = {}
    seen: set[str] = set()

    def add(o: dict) -> None:
        uid = o.get("uid")
        if not uid or uid in seen:
            return
        seen.add(uid)
        for m in o.get("members") or []:          # pull nested group/service-group members up too
            if isinstance(m, dict):
                add(m)
            elif isinstance(m, str) and m in objdict:
                add(objdict[m])
        if mgmt_export.is_predefined(o):
            return
        by_type.setdefault(o.get("type") or "unknown", []).append(o)

    for o in list(objdict.values()):
        add(o)
    return by_type


def pull_for_export(server, secret: str, layer: str, max_rules: int = 5000) -> dict:
    """Pull a layer's rulebase with FULL object details, returning the structured rows plus the
    referenced objects grouped by type. Feeds ``mgmt_export.generate`` — no rendering here."""
    with MgmtSession(server, secret) as s:
        items: list[dict] = []
        objdict: dict = {}
        total, offset = 0, 0
        while offset < max_rules:
            page = s.call("show-access-rulebase",
                          {"name": layer, "limit": 100, "offset": offset,
                           "use-object-dictionary": True, "details-level": "full"})
            for o in page.get("objects-dictionary", []):
                if o.get("uid"):
                    objdict[o["uid"]] = o
            batch = page.get("rulebase", [])
            items.extend(batch)
            total = page.get("total", total)
            to = page.get("to", 0)
            if not batch or to >= total or to <= offset:
                break
            offset = to
        rows = _structure_rulebase(items, objdict)
        return {"layer": layer, "rules": rows, "objects_by_type": _collect_export_objects(objdict),
                "total": total, "trace": s.trace}


def test_connection(server, secret: str) -> dict:
    """Login, read the API version + domains, log out. Returns {ok, version, domains, layers, trace}."""
    out: dict = {"ok": False, "version": "", "domains": [], "layers": 0, "trace": [], "message": ""}
    try:
        with MgmtSession(server, secret) as s:
            ver = s.call("show-api-versions")
            out["version"] = ver.get("current-version", "")
            out["domains"] = [d.get("name") for d in s.show_domains() if d.get("name")]
            out["layers"] = len(s.list_access_layers())
            out["ok"] = True
            out["trace"] = s.trace
    except MgmtError as exc:
        out["message"] = str(exc)
    except Exception as exc:  # noqa: BLE001 — surface anything unexpected as a clean message
        out["message"] = f"Unexpected error: {exc}"
    return out
