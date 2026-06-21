"""Generic ticketing / ITSM webhook integration for access automation.

Vendor-neutral: any system that can POST JSON — ServiceNow, Jira, Remedy, Cherwell, Freshservice, a
custom portal, or plain curl — can drive the access-automation webhook. Inbound bodies are parsed with
generous field aliases into a canonical request; the result can be written back two ways:

  * GENERIC  -- the caller supplies a ``callback_url`` and we POST the result JSON there (works for any
               vendor that exposes an inbound endpoint, and for the synchronous-response pattern too),
  * BUILT-IN -- the ServiceNow Table API adapter writes a work note to the incident (DCSIM_SERVICENOW_*).

Security: TLS verification is ALWAYS on (never a skip-verify path). Inbound auth — the shared
``DCSIM_WEBHOOK_TOKEN`` checked as ``X-DCSim-Token`` — is enforced by the router BEFORE this module runs,
so a supplied ``callback_url`` always comes from an already-authenticated caller. Credentials come from
env, never hardcoded.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Optional

import httpx

from ..config import get_settings
from .access_automation import AccessRequest

_TRUE = {"1", "true", "yes", "y", "on", "apply", "publish"}


@dataclass
class TicketRequest:
    ticket_id: str
    server_id: int
    layer: str
    request: AccessRequest
    apply: bool                         # True -> apply + publish; False -> preview/validate only
    package: Optional[str] = None
    callback_url: Optional[str] = None  # optional: where to POST the result back to (any vendor)
    callback_token: Optional[str] = None


def _first(data: dict, *names, default=None):
    for n in names:
        if n in data and data[n] not in (None, ""):
            return data[n]
    return default


def _norm_cidr(value: str) -> str:
    """A bare IP becomes /32 (/128 for v6); a CIDR is validated and normalised. Raises ValueError."""
    value = str(value).strip()
    if not value:
        raise ValueError("missing address")
    if "/" not in value:
        ip = ipaddress.ip_address(value)               # raises on garbage
        value = f"{value}/{32 if ip.version == 4 else 128}"
    return str(ipaddress.ip_network(value, strict=False))


def _validate_port(port) -> str:
    """One service per request: a single numeric port, or a single lo-hi range. Rejects comma lists,
    named services and out-of-range values up front so the request never reaches the engine malformed
    (a bad port here becomes a clean 400, not an HTTP 500 deep in resolve_service)."""
    port = str(port or "").strip()
    if not port:
        raise ValueError("port is required.")
    if "," in port:
        raise ValueError("port must be a single value or a single lo-hi range, not a comma list.")
    parts = port.split("-")
    if len(parts) > 2:
        raise ValueError("port range must be 'lo-hi'.")
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        raise ValueError(f"port must be numeric (got {port!r}).")
    if any(n < 0 or n > 65535 for n in nums):
        raise ValueError("port must be between 0 and 65535.")
    if len(nums) == 2 and nums[0] > nums[1]:
        raise ValueError("port range must have lo <= hi.")
    return port


def build_request(source, destination, protocol, port, application=None) -> AccessRequest:
    """Validate + normalise a raw tuple into an AccessRequest. Shared by the UI and the webhook. When
    `application` is given (e.g. "Facebook") it's an app request and protocol/port are ignored.
    Raises ValueError (clean message) on anything malformed."""
    if source in (None, "") or destination in (None, ""):
        raise ValueError("source and destination are required.")
    try:
        src_cidr, dst_cidr = _norm_cidr(source), _norm_cidr(destination)
    except ValueError as exc:
        raise ValueError(f"Invalid source/destination: {exc}")
    application = str(application).strip() if application else ""
    if application:
        return AccessRequest(src_cidrs=[src_cidr], dst_cidrs=[dst_cidr], application=application)
    protocol = str(protocol or "tcp").lower()
    if protocol not in ("tcp", "udp"):
        raise ValueError("protocol must be 'tcp' or 'udp'.")
    return AccessRequest(src_cidrs=[src_cidr], dst_cidrs=[dst_cidr],
                         protocol=protocol, ports=_validate_port(port))


def parse_payload(data: dict) -> TicketRequest:
    """Build a TicketRequest from a webhook body, accepting common vendor field aliases (ServiceNow
    ``u_*`` / ``number`` / ``sys_id``, Jira ``key``, plus plain names). Raises ValueError on anything
    malformed so the router can return a clean 400."""
    if not isinstance(data, dict):
        raise ValueError("Expected a JSON object body.")

    ticket_id = str(_first(data, "ticket_id", "ticket", "number", "key", "id", "request_id",
                            "u_number", "sys_id", default="")).strip()
    server_raw = _first(data, "server_id", "management_server_id", "sms_id", "u_server_id")
    if server_raw in (None, ""):
        raise ValueError("server_id is required (which saved management server to target).")
    try:
        server_id = int(server_raw)
    except (TypeError, ValueError):
        raise ValueError("server_id must be a number.")

    layer = str(_first(data, "layer", "policy_layer", "u_layer", default="")).strip()
    if not layer:
        raise ValueError("layer is required (the access layer name to evaluate).")

    req = build_request(
        _first(data, "source", "src", "source_ip", "u_source"),
        _first(data, "destination", "dst", "dest", "destination_ip", "u_destination"),
        _first(data, "protocol", "proto", "u_protocol", default="tcp"),
        _first(data, "port", "ports", "service_port", "u_port", default=""),
        _first(data, "application", "app", "u_application"),
    )
    apply_flag = str(_first(data, "apply", "commit", "u_apply", default="")).strip().lower() in _TRUE
    return TicketRequest(
        ticket_id=ticket_id, server_id=server_id, layer=layer, request=req, apply=apply_flag,
        package=_first(data, "package", "u_package"),
        callback_url=_first(data, "callback_url", "callbackUrl", "callback", "response_url",
                            "u_callback_url"),
        callback_token=_first(data, "callback_token", "callbackToken"),
    )


# --------------------------------------------------------------------------- #
# Result write-back
# --------------------------------------------------------------------------- #
def summarize(result: dict, ticket_id: str = "") -> str:
    """A compact work-note line from an execute()/preview() result."""
    if not result.get("ok"):
        return f"[DC-Sim] access automation FAILED: {result.get('error', 'unknown error')}"
    bits = [f"[DC-Sim] outcome={result.get('outcome', '?')}", result.get("reason", "")]
    for key, label in (("source_object", "source"), ("destination_object", "destination"),
                       ("service_object", "service"), ("position", "position")):
        if result.get(key):
            bits.append(f"{label}={result[key]}")
    tgt = result.get("target_rule")
    if tgt:
        bits.append(f"rule={tgt.get('uid')}")
    bits.append("published" if result.get("published") else
                ("validated (not committed)" if result.get("applied") else "no change"))
    return " | ".join(b for b in bits if b)


def notify(ticket: TicketRequest, result: dict) -> dict:
    """Push the result back to the originating system. Dispatch order:
       1. a generic ``callback_url`` the (authenticated) caller supplied -> POST the result JSON,
       2. otherwise the built-in ServiceNow Table API adapter, if configured,
       3. otherwise nothing (the caller already has the synchronous response)."""
    if ticket.callback_url:
        return _post_callback(ticket, result)
    if servicenow_configured():
        return update_servicenow(ticket.ticket_id, summarize(result, ticket.ticket_id))
    return {"skipped": "no callback_url supplied and no ServiceNow callback configured"}


def _post_callback(ticket: TicketRequest, result: dict) -> dict:
    """Generic write-back: POST the result to the caller-supplied URL. TLS verification stays on; the
    optional ``callback_token`` is echoed as X-DCSim-Token so the receiver can authenticate us."""
    headers = {"Content-Type": "application/json"}
    if ticket.callback_token:
        headers["X-DCSim-Token"] = ticket.callback_token
    payload = {"ticket_id": ticket.ticket_id, "applied": ticket.apply,
               "outcome": result.get("outcome"), "summary": summarize(result, ticket.ticket_id),
               "result": result}
    try:
        with httpx.Client(timeout=15.0, verify=True) as c:   # TLS verification ALWAYS on
            r = c.post(ticket.callback_url, json=payload, headers=headers)
            return {"ok": r.status_code in (200, 201, 202, 204), "status": r.status_code,
                    "via": "callback_url"}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"callback POST failed: {exc}", "via": "callback_url"}


# --- built-in ServiceNow Table API adapter (optional) ----------------------------------------
def servicenow_configured() -> bool:
    s = get_settings()
    return bool(s.servicenow_instance and s.servicenow_user and s.servicenow_password)


def update_servicenow(ticket_id: str, work_notes: str, fields: Optional[dict] = None) -> dict:
    """Append a work note (and optional fields) to a ServiceNow incident via the Table API. Best-effort
    and config-guarded; returns {skipped} when not configured. TLS verification stays on."""
    if not servicenow_configured():
        return {"skipped": "ServiceNow callback not configured"}
    if not ticket_id:
        return {"skipped": "no ticket id to update"}
    s = get_settings()
    base = s.servicenow_instance.rstrip("/")
    table = s.servicenow_table or "incident"
    auth = (s.servicenow_user, s.servicenow_password)
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    body = {"work_notes": work_notes, **(fields or {})}
    try:
        with httpx.Client(timeout=15.0, verify=True) as c:   # TLS verification ALWAYS on
            sys_id = ticket_id
            if not _looks_like_sys_id(ticket_id):
                r = c.get(f"{base}/api/now/table/{table}", auth=auth, headers=headers,
                          params={"sysparm_query": f"number={ticket_id}",
                                  "sysparm_fields": "sys_id", "sysparm_limit": 1})
                rows = (r.json().get("result") or []) if r.status_code == 200 else []
                if not rows:
                    return {"ok": False, "error": f"incident {ticket_id} not found", "via": "servicenow"}
                sys_id = rows[0]["sys_id"]
            r = c.patch(f"{base}/api/now/table/{table}/{sys_id}", auth=auth, headers=headers, json=body)
            return {"ok": r.status_code in (200, 201), "status": r.status_code, "sys_id": sys_id,
                    "via": "servicenow"}
    except httpx.HTTPError as exc:
        return {"ok": False, "error": f"ServiceNow callback failed: {exc}", "via": "servicenow"}


def _looks_like_sys_id(value: str) -> bool:
    return len(value) == 32 and all(c in "0123456789abcdef" for c in value.lower())
