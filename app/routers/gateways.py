"""Saved gateway connection profiles (name, host, port, username, pinned cert). No password
is ever stored — it's entered per apply. Each Dynamic Layer can be associated with a gateway."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import DynamicLayer, Gateway, User
from ..security import get_user_or_none, new_feed_token
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)


def _owned(db: Session, gid: int, user: User) -> Gateway:
    gw = db.get(Gateway, gid)
    if gw is None or gw.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Gateway not found")
    return gw


def _port(value: str) -> int:
    try:
        return int(value or 443)
    except ValueError:
        return 443


@router.get("/gateways", response_class=HTMLResponse)
def gateways_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gws = db.scalars(
        select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.created_at.desc())
    ).all()
    layers = db.scalars(select(DynamicLayer).where(DynamicLayer.owner_id == user.id)).all()
    counts: dict[int, int] = {}
    for layer in layers:
        gid = (layer.content or {}).get("gateway_id")
        if gid:
            counts[gid] = counts.get(gid, 0) + 1
    rows = [{"gw": g, "layers": counts.get(g.id, 0)} for g in gws]
    return templates.TemplateResponse(request, "gateway_list.html", {"rows": rows, "flash": _pop_flash(request)})


@router.get("/gateways/new", response_class=HTMLResponse)
def gateways_new(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "gateway_form.html",
                                      {"gw": None, "error": None, "action": "/gateways/new"})


@router.post("/gateways/new")
def gateways_create(request: Request, name: str = Form(...), host: str = Form(...),
                    port: str = Form("443"), username: str = Form(""), cert_pem: str = Form(""),
                    db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = Gateway(token=new_feed_token(), name=name, host=host, port=_port(port),
                 username=username, cert_pem=cert_pem, owner_id=user.id)
    db.add(gw)
    db.commit()
    _flash(request, f"Gateway “{name}” saved.")
    return RedirectResponse("/gateways", status_code=303)


@router.get("/gateways/{gid}/edit", response_class=HTMLResponse)
def gateways_edit(gid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    return templates.TemplateResponse(request, "gateway_form.html",
                                      {"gw": gw, "error": None, "action": f"/gateways/{gid}/edit"})


@router.post("/gateways/{gid}/edit")
def gateways_update(gid: int, request: Request, name: str = Form(...), host: str = Form(...),
                    port: str = Form("443"), username: str = Form(""), cert_pem: str = Form(""),
                    db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    gw.name, gw.host, gw.port, gw.username, gw.cert_pem = name, host, _port(port), username, cert_pem
    db.commit()
    _flash(request, f"Gateway “{name}” updated.")
    return RedirectResponse("/gateways", status_code=303)


@router.post("/gateways/{gid}/delete")
def gateways_delete(gid: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gw = _owned(db, gid, user)
    name = gw.name
    db.delete(gw)
    db.commit()
    _flash(request, f"Gateway “{name}” deleted.")
    return RedirectResponse("/gateways", status_code=303)
