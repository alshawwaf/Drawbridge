"""The agent-facing capabilities exposed over MCP (and reusable anywhere) — PURE functions that return
plain JSON-serializable dicts, with NO dependency on the MCP SDK. ``mcp_server`` wraps these as MCP tools;
this module is what the tests exercise and what keeps the SDK glue thin.

Each tool resolves its own management server + credential from the DB (the MCP server runs outside the
HTTP request lifecycle), mirroring the webhook. Reads/preview/correlate/coverage are always available;
``apply_access`` can validate (dry-run) freely but only PUBLISHES when the admin has turned on the
``mcp_allow_publish`` setting — an LLM never commits to live policy by default."""
from __future__ import annotations

from ..db import SessionLocal
from ..models import ManagementServer


def _server_secret(db, server_id: int):
    """(ManagementServer, secret) for ``server_id`` or a ValueError the caller turns into {"error": …}."""
    from . import mgmt_creds
    ms = db.get(ManagementServer, int(server_id))
    if ms is None:
        raise ValueError(f"management server {server_id} not found")
    if not ms.username:
        raise ValueError(f"management server {server_id} has no username configured")
    secret = mgmt_creds.get_secret(db, ms)
    if not secret:
        raise ValueError(f"management server {server_id} has no stored credential")
    try:
        from .gaia_client import ensure_pinned
        ensure_pinned(db, ms)            # trust-on-first-use before the TLS handshake
    except Exception:  # noqa: BLE001 — pinning is best-effort; the call still verifies the saved cert
        pass
    return ms, secret


def list_management_servers() -> dict:
    """The Check Point management servers Drawbridge knows about (so an agent can pick a target)."""
    db = SessionLocal()
    try:
        rows = db.query(ManagementServer).all()
        return {"servers": [{"id": m.id, "name": m.name, "host": m.host, "port": m.port,
                             "domain": m.domain or ""} for m in rows]}
    finally:
        db.close()


def list_access_layers(server_id: int) -> dict:
    """The access layers (policy rulebases) on a server, so the agent names a real layer."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            layers = [L.get("name") for L in s.list_access_layers() if L.get("name")]
        return {"server_id": int(server_id), "layers": layers}
    except MgmtError as exc:
        return {"error": str(exc)}


def _build(source, destination, service, port, protocol, application):
    from . import ticketing
    return ticketing.build_request(source, destination, protocol or "tcp", port or "",
                                   application=application, service=service)


def decide_access(server_id: int, source: str, destination: str, layer: str, service: str | None = None,
                  port: str | None = None, protocol: str = "tcp", application: str | None = None,
                  package: str | None = None) -> dict:
    """PREVIEW (read-only) what Drawbridge would do for an access request: returns the outcome
    (no_op / widen / create / review), the reasoning, and — for an unknown service/app — `suggestions`.
    Writes nothing. This is the primary tool for an agent to reason about a change."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()
    from . import access_automation as aa
    try:
        req = _build(source, destination, service, port, protocol, application)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return aa.preview(ms, secret, req, layer, package=package)


def apply_access(server_id: int, source: str, destination: str, layer: str, service: str | None = None,
                 port: str | None = None, protocol: str = "tcp", application: str | None = None,
                 package: str | None = None, publish: bool = False, ticket_id: str = "") -> dict:
    """APPLY an access request. With publish=false it DRY-RUNS (applies inside a session, then discards —
    nothing is committed) — always allowed. With publish=true it COMMITS to the live server — allowed ONLY
    when an admin has enabled the 'mcp_allow_publish' setting; otherwise it's refused (dry-run instead)."""
    if publish:
        from . import app_settings
        try:
            allowed = bool(app_settings.get("mcp_allow_publish"))
        except Exception:  # noqa: BLE001
            allowed = False
        if not allowed:
            return {"ok": False, "outcome": "review", "applied": False, "published": False,
                    "error": "publishing is disabled for the MCP agent — an admin must enable "
                             "'Let the MCP agent publish to live policy' in Settings. Re-run with "
                             "publish=false to dry-run (validate then discard)."}
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        db.close()
    from . import access_automation as aa
    try:
        req = _build(source, destination, service, port, protocol, application)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    return aa.execute(ms, secret, req, layer, package=package, ticket_id=ticket_id, publish=publish)


def correlate_service(server_id: int, name: str) -> dict:
    """Map a service/protocol name (icmp, GRE, sctp, …) to the real Check Point service object, or return
    candidate matches ('did you mean'). Lets an agent fix a name before deciding."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from . import services
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            return services.resolve(s, name)
    except MgmtError as exc:
        return {"error": str(exc)}


def correlate_application(server_id: int, name: str) -> dict:
    """Map an application/site name (Facebook, …) to the real Check Point application-site object, or
    return candidates."""
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    except ValueError as exc:
        db.close()
        return {"error": str(exc)}
    db.close()
    from . import applications
    from .mgmt_api import MgmtError, read_session
    try:
        with read_session(ms, secret) as s:
            return applications.resolve(s, name)
    except MgmtError as exc:
        return {"error": str(exc)}


def _load_layer_rules(server_id: int, layer: str):
    db = SessionLocal()
    try:
        ms, secret = _server_secret(db, server_id)
    finally:
        db.close()
    from . import access_automation as aa
    from .mgmt_api import read_session
    with read_session(ms, secret) as s:
        rules, _ = aa.load_layer_cached(s, ms, layer)
    return rules


def summarize_layer(server_id: int, layer: str) -> dict:
    """A high-level overview of an access layer (read-only): rule counts, Accept/Drop split, how many
    rules are Any on source/destination/service, inline layers, whether a cleanup drop exists."""
    try:
        rules = _load_layer_rules(server_id, layer)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    from . import access_automation as aa
    return {"server_id": int(server_id), "layer": layer, "summary": aa.summarize_rules(rules)}


def analyze_policy(server_id: int, layer: str) -> dict:
    """Read-only policy INSIGHTS for an access layer: the summary, plus rules that can never match
    (shadowed by an earlier broader Accept/Drop) and overly-permissive Accept rules (Any on a whole
    dimension) — to help tighten the policy. Provably-conservative: only flags what it can prove."""
    try:
        rules = _load_layer_rules(server_id, layer)
    except Exception as exc:  # noqa: BLE001
        return {"error": str(exc)}
    from . import access_automation as aa
    return {"server_id": int(server_id), "layer": layer,
            "summary": aa.summarize_rules(rules),
            "shadowed_rules": aa.find_shadowed(rules),
            "overly_permissive": aa.find_permissive(rules)}


def coverage_lookup(api: str = "management", name: str = "", version: str = "") -> dict:
    """Is a Check Point object (and its fields) supported by the Terraform provider / Ansible collection?
    With ``name`` returns that object's per-field 3-way support; without, the object list for the api."""
    from . import coverage
    api = api if api in ("management", "gaia") else "management"
    ver = version or coverage.latest(api)
    if name:
        detail = coverage.object_detail(api, ver, name)
        if not detail or detail.get("error"):       # object_detail returns {"error": …} for an unknown name
            return {"error": f"no object “{name}” in {api} {ver}",
                    "objects": [o["name"] for g in coverage.object_groups(api, ver) for o in g["rows"]][:50]}
        return detail
    return {"api": api, "version": ver,
            "objects": [o["name"] for g in coverage.object_groups(api, ver) for o in g["rows"]]}
