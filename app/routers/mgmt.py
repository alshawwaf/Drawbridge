"""Saved Check Point Management Server / MDS-domain profiles, driven over the `web_api`.

Phase 1: connection profiles (encrypted secret, pinned/auto-trust TLS) + Test Connection. The policy
viewer, IaC export, and CRUD build on this. Mirrors the Gateways router; the login password / API key
is stored AES-256-GCM (mgmt_creds) and TLS verification is never disabled.
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ManagementServer, User
from ..security import get_user_or_none
from ..services import mgmt_api, mgmt_creds
from ..services.gaia_client import ensure_pinned, fetch_gateway_cert
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)


def _owned(db: Session, sid: int, user: User) -> ManagementServer:
    ms = db.get(ManagementServer, sid)
    if ms is None or ms.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Management server not found")
    return ms


def _port(value: str) -> int:
    try:
        return int(value or 443)
    except ValueError:
        return 443


@router.get("/management", response_class=HTMLResponse)
def mgmt_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    servers = db.scalars(
        select(ManagementServer).where(ManagementServer.owner_id == user.id)
        .order_by(ManagementServer.created_at.desc())
    ).all()
    rows = [{"ms": m, "has_secret": mgmt_creds.has_secret(db, m)} for m in servers]
    return templates.TemplateResponse(request, "management_list.html",
                                      {"rows": rows, "flash": _pop_flash(request)})


@router.get("/management/new", response_class=HTMLResponse)
def mgmt_new(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "management_form.html",
                                      {"ms": None, "error": None, "action": "/management/new",
                                       "has_secret": False, "crypto_ok": mgmt_creds.available()})


@router.post("/management/new")
def mgmt_create(request: Request, name: str = Form(...), host: str = Form(...), port: str = Form("443"),
                username: str = Form(""), domain: str = Form(""), cert_pem: str = Form(""),
                password: str = Form(""), auto_trust: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = ManagementServer(name=name, host=host, port=_port(port), username=username,
                          domain=domain.strip(), cert_pem=cert_pem, auto_trust=bool(auto_trust),
                          owner_id=user.id)
    db.add(ms)
    db.commit()
    db.refresh(ms)
    note = ""
    if password and mgmt_creds.available():
        mgmt_creds.store_secret(db, ms, password, kind="password")
    elif password:
        note = " (the secret was not stored — encryption is unavailable in this environment)"
    msg = f"Management server “{name}” saved.{note}"
    if ms.auto_trust and not ms.cert_pem:
        msg += " Its certificate is pinned on the first connect."
    _flash(request, msg, "error" if note else "success")
    return RedirectResponse("/management", status_code=303)


@router.post("/management/fetch-cert")
def mgmt_fetch_cert(request: Request, host: str = Form(""), port: str = Form("443"),
                    db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if not host:
        return JSONResponse({"error": "Enter the management address first."}, status_code=400)
    try:
        return JSONResponse(fetch_gateway_cert(host, _port(port)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"Could not fetch certificate from {host}:{_port(port)} — {exc}"},
                            status_code=400)


@router.post("/management/{sid}/test")
def mgmt_test(sid: int, request: Request, password: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    ms = _owned(db, sid, user)
    ensure_pinned(db, ms)   # trust-on-first-use: pin the presented cert before the TLS handshake
    secret = password or mgmt_creds.get_secret(db, ms)
    if not ms.username:
        return JSONResponse({"ok": False, "message": "This server has no username — set one first."})
    if not secret:
        return JSONResponse({"ok": False, "message": "No saved credential — enter the password, or "
                            "store one on the Edit page."})
    return JSONResponse(mgmt_api.test_connection(ms, secret))


@router.get("/management/{sid}/edit", response_class=HTMLResponse)
def mgmt_edit(sid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    return templates.TemplateResponse(request, "management_form.html",
                                      {"ms": ms, "error": None, "action": f"/management/{sid}/edit",
                                       "has_secret": mgmt_creds.has_secret(db, ms),
                                       "crypto_ok": mgmt_creds.available()})


@router.post("/management/{sid}/edit")
def mgmt_update(sid: int, request: Request, name: str = Form(...), host: str = Form(...),
                port: str = Form("443"), username: str = Form(""), domain: str = Form(""),
                cert_pem: str = Form(""), password: str = Form(""), clear_password: str = Form(""),
                auto_trust: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    ms.name, ms.host, ms.port, ms.username = name, host, _port(port), username
    ms.domain, ms.cert_pem, ms.auto_trust = domain.strip(), cert_pem, bool(auto_trust)
    note = ""
    if clear_password:
        mgmt_creds.clear_secret(db, ms)
    elif password:
        if mgmt_creds.available():
            mgmt_creds.store_secret(db, ms, password, kind="password")
        else:
            note = " (the new secret was not stored — encryption is unavailable here)"
    db.commit()
    _flash(request, f"Management server “{name}” updated.{note}", "error" if note else "success")
    return RedirectResponse("/management", status_code=303)


@router.post("/management/{sid}/delete")
def mgmt_delete(sid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ms = _owned(db, sid, user)
    name = ms.name
    db.delete(ms)
    db.commit()
    _flash(request, f"Management server “{name}” deleted.")
    return RedirectResponse("/management", status_code=303)
