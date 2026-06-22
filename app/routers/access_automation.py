"""Ticket-driven access automation: turn an access request into the minimal correct change on a
Check Point access layer (no-op / widen / create), over the ``web_api``.

Three surfaces, all reusing the saved Management Server profiles + encrypted secret:
  * the UI request form (preview, then dry-run validate or publish),
  * JSON preview / apply endpoints the form calls,
  * a token-authenticated ServiceNow webhook for end-to-end automation.

The decision engine + API call sequence live in ``services.access_automation``; payload parsing and
the optional write-back in ``services.ticketing``. Approvals are out of scope (your ITSM owns them).
"""
import hmac

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import ManagementServer, User
from ..security import get_user_or_none
from ..services import access_automation as aa
from ..services import applications, decision_tree, mgmt_api, mgmt_creds, services, table_prefs, ticketing
from ..services.gaia_client import ensure_pinned
from .ui import _pop_flash, templates

router = APIRouter(include_in_schema=False)


class AccessReqBody(BaseModel):
    layer: str
    source: str
    destination: str
    protocol: str = "tcp"
    port: str = ""
    application: str | None = None      # an application-site name (e.g. "Facebook") — overrides everything
    service: str | None = None          # a named non-port service (e.g. "icmp", "GRE") — overrides port
    ticket_id: str = ""
    publish: bool = False
    package: str | None = None


def _owned(db: Session, sid: int, user: User) -> ManagementServer:
    ms = db.get(ManagementServer, sid)
    if ms is None or ms.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Management server not found")
    return ms


def _secret_or_error(db: Session, ms: ManagementServer):
    """Resolve the stored secret for a live call, or a JSONResponse error if it can't run."""
    if not ms.username:
        return None, JSONResponse({"error": "This server has no username — set one on Edit."},
                                  status_code=400)
    secret = mgmt_creds.get_secret(db, ms)
    if not secret:
        return None, JSONResponse({"error": "No saved credential — store one on the Edit page to run "
                                  "access automation."}, status_code=400)
    ensure_pinned(db, ms)   # trust-on-first-use before the TLS handshake
    return secret, None


# --- UI -------------------------------------------------------------------------------------
@router.get("/access-automation", response_class=HTMLResponse)
def aa_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    rows = [{"ms": m, "has_secret": mgmt_creds.has_secret(db, m)} for m in servers]
    return templates.TemplateResponse(request, "access_automation_list.html",
                                      {"rows": rows, "flash": _pop_flash(request),
                                       "cols": table_prefs.spec("access-servers"),
                                       "vis": table_prefs.visible_columns(db, user.id, "access-servers")})


@router.get("/access-automation/decision-tree/{fmt}")
def aa_decision_tree(fmt: str, request: Request, db: Session = Depends(get_db)):
    """Download the decision tree as a portable diagram: .drawio (diagrams.net / → Visio), .mmd
    (Mermaid), or .dot (Graphviz). Generated from the single source of truth in services.decision_tree
    so it always matches the engine. Registered BEFORE /{sid} so the literal path wins over the int id."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    spec = decision_tree.RENDERERS.get(fmt)
    if spec is None:
        return PlainTextResponse("Unknown format.", status_code=404)
    render, ctype, ext = spec
    return PlainTextResponse(render(), media_type=ctype, headers={
        "Content-Disposition": f'attachment; filename="drawbridge-decision-tree.{ext}"'})


@router.get("/access-automation/{sid}", response_class=HTMLResponse)
def aa_detail(sid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    # Bake the COLLAPSED (core-flow) view as the initial paint so the no-JS / CDN-blocked fallback isn't
    # overwhelming; the client rebuilds from decision_graph and expands the detail tiers on demand.
    import json
    dv = decision_tree.default_visible()
    return templates.TemplateResponse(request, "access_automation_detail.html",
                                      {"ms": ms, "has_secret": mgmt_creds.has_secret(db, ms),
                                       "decision_mermaid_dark": decision_tree.to_mermaid(True, dv),
                                       "decision_mermaid_light": decision_tree.to_mermaid(False, dv),
                                       "decision_graph_json": json.dumps(
                                           decision_tree.to_graph()).replace("<", "\\u003c"),
                                       "flash": _pop_flash(request)})


def _run(db: Session, sid: int, user: User, body: AccessReqBody, *, do_apply: bool):
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    try:
        req = ticketing.build_request(body.source, body.destination, body.protocol, body.port,
                                      body.application, body.service)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    if not body.layer:
        return JSONResponse({"error": "No layer specified."}, status_code=400)
    if do_apply:
        result = aa.execute(ms, secret, req, body.layer, package=body.package,
                            ticket_id=body.ticket_id, publish=body.publish)
    else:
        result = aa.preview(ms, secret, req, body.layer, package=body.package)
    code = 200 if result.get("ok") else 400
    return JSONResponse(result, status_code=code)


@router.get("/access-automation/{sid}/app-search")
def aa_app_search(sid: int, request: Request, q: str = "", db: Session = Depends(get_db)):
    """Type-ahead: real Check Point applications matching ``q`` on this server (for the Application
    field + the 'did you mean' chips). Best-effort — returns [] rather than erroring the UI."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return JSONResponse({"candidates": []})
    try:
        return JSONResponse({"candidates": applications.search_server(ms, secret, q)})
    except Exception:  # noqa: BLE001
        return JSONResponse({"candidates": []})


@router.get("/access-automation/{sid}/svc-search")
def aa_svc_search(sid: int, request: Request, q: str = "", kind: str = "", db: Session = Depends(get_db)):
    """Type-ahead: real Check Point services matching ``q`` (icmp, GRE, GTP, …). ``kind`` (the picked
    Service type: icmp/rpc/dce-rpc/gtp/other/…) narrows the suggestions to that object type so the right
    object is offered. Best-effort -> []."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return JSONResponse({"candidates": []})
    try:
        return JSONResponse({"candidates": services.search_server(ms, secret, q, kind=kind)})
    except Exception:  # noqa: BLE001
        return JSONResponse({"candidates": []})


@router.post("/access-automation/{sid}/preview")
def aa_preview(sid: int, body: AccessReqBody, request: Request, db: Session = Depends(get_db)):
    """JSON: load → decide → describe what would happen. Read-only, commits nothing."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return _run(db, sid, user, body, do_apply=False)


class TakeOverBody(BaseModel):
    session_uid: str


@router.post("/access-automation/{sid}/take-over")
def aa_take_over(sid: int, body: TakeOverBody, request: Request, db: Session = Depends(get_db)):
    """Release a 'Locked for editing' conflict by taking over the offending session and discarding its
    uncommitted changes. DESTRUCTIVE — the UI confirms first. Returns {ok} / {error}."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    secret, err = _secret_or_error(db, ms)
    if err:
        return err
    if not (body.session_uid or "").strip():
        return JSONResponse({"error": "No session id."}, status_code=400)
    res = mgmt_api.take_over_session(ms, secret, body.session_uid.strip())
    return JSONResponse(res, status_code=200 if res.get("ok") else 400)


@router.post("/access-automation/{sid}/apply")
def aa_apply(sid: int, body: AccessReqBody, request: Request, db: Session = Depends(get_db)):
    """JSON: apply the change. ``publish:false`` validates then discards (zero commit);
    ``publish:true`` commits it."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return _run(db, sid, user, body, do_apply=True)


# --- Generic ticketing webhook (no portal session; authenticated by a shared token) ----------
def _allowed_server_ids() -> set:
    """Optional allowlist (DCSIM_WEBHOOK_SERVER_IDS, comma-separated). Empty = every saved server."""
    raw = (get_settings().webhook_server_ids or "").replace(" ", "")
    return {int(p) for p in raw.split(",") if p.isdigit()}


@router.post("/access-automation/webhook")
async def aa_webhook(request: Request, db: Session = Depends(get_db)):
    """End-to-end automation for ANY ticketing system (ServiceNow, Jira, Remedy, a custom portal,
    curl …): the caller POSTs an access request → we decide + (optionally) apply → return the result
    JSON, and push it back via the caller's ``callback_url`` or the built-in ServiceNow adapter.

    Auth: the shared secret DCSIM_WEBHOOK_TOKEN must arrive as the X-DCSim-Token header. If the token
    is unset the webhook is DISABLED (503) — it never runs unauthenticated. The token grants policy
    publish on every allowed management server, so treat it as a top-tier secret; optionally scope it
    with DCSIM_WEBHOOK_SERVER_IDS."""
    token = get_settings().webhook_token
    if not token:
        return JSONResponse({"error": "Webhook disabled — set DCSIM_WEBHOOK_TOKEN to enable it."},
                            status_code=503)
    if not hmac.compare_digest(request.headers.get("x-dcsim-token", ""), token):
        return JSONResponse({"error": "Invalid or missing X-DCSim-Token."}, status_code=401)

    try:
        data = await request.json()
    except Exception:  # noqa: BLE001
        return JSONResponse({"error": "Body must be JSON."}, status_code=400)
    try:
        ticket = ticketing.parse_payload(data)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    allow = _allowed_server_ids()
    if allow and ticket.server_id not in allow:
        return JSONResponse({"error": f"server_id {ticket.server_id} is not in the webhook allowlist."},
                            status_code=403)

    ms = db.get(ManagementServer, ticket.server_id)
    if ms is None:
        return JSONResponse({"error": f"Management server {ticket.server_id} not found."},
                            status_code=404)
    if not ms.username:
        return JSONResponse({"error": "Target server has no username configured."}, status_code=400)
    secret = mgmt_creds.get_secret(db, ms)
    if not secret:
        return JSONResponse({"error": "Target server has no stored credential."}, status_code=400)
    ensure_pinned(db, ms)

    if ticket.apply:
        result = aa.execute(ms, secret, ticket.request, ticket.layer, package=ticket.package,
                            ticket_id=ticket.ticket_id, publish=True)
    else:
        result = aa.preview(ms, secret, ticket.request, ticket.layer, package=ticket.package)

    # Push the result back to the originating system (generic callback_url, or the ServiceNow adapter).
    callback = ticketing.notify(ticket, result)
    return JSONResponse({"ticket_id": ticket.ticket_id, "applied": ticket.apply,
                         "result": result, "callback": callback},
                        status_code=200 if result.get("ok") else 400)
