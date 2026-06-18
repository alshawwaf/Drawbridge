"""Mock Cisco ACI / APIC (REST) that CloudGuard Controller R82.10 connects to.

**CloudGuard's APIC client uses only the HOST from the *URLs* field** (it discards any path), then
calls ``/api/aaaLogin.xml`` and ``/api/node/class/<class>.xml`` at the root — confirmed from a trace
(a path-based ``/aci/<token>/...`` mock 404'd, and the controller XML-parsed the 404 JSON → "Content
is not allowed in prolog"). So ACI is served at the **apex** (resolving the most-recently created ACI
datacenter — one ACI per portal), exactly like vCenter/NSX-T. ``/api/aaaLogin``, ``/api/node|class|mo``
don't collide with the NSX-T family's ``/api/session`` + ``/api/v1``. Token routes
(``/aci/<token>/api/...``) are kept for direct testing.

**The client unmarshals XML unconditionally** (`apic_service.jar` → JAXB; JSON → prolog error), so the
mock answers APIC XML — ``<imdata totalCount="N"><fvTenant .../>…</imdata>``. Login returns a token
echoed back as the ``APIC-cookie``. Every call is in the Activity log.
"""
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter
from ..services import aci

router = APIRouter(tags=["aci-mock"])


def _apex_dc(db: Session) -> Datacenter:
    """The single ACI datacenter served at the root (most-recently created), since the controller
    strips the URL to the bare host."""
    dc = db.scalar(select(Datacenter).where(Datacenter.provider == "aci")
                   .order_by(Datacenter.created_at.desc()))
    if dc is None:
        raise HTTPException(status_code=404, detail="No ACI datacenter configured")
    return dc


def _dc(db: Session, token: str) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.token == token, Datacenter.provider == "aci"))
    if dc is None:
        raise HTTPException(status_code=404, detail="ACI datacenter not found")
    return dc


def _creds(raw: bytes):
    """Pull (name, pwd) out of the aaaLogin body: {"aaaUser":{"attributes":{"name","pwd"}}}."""
    try:
        attrs = ((json.loads(raw or b"{}").get("aaaUser") or {}).get("attributes")) or {}
        return attrs.get("name", ""), attrs.get("pwd", "")
    except Exception:
        return "", ""


def _xml(objs: list, status: int = 200) -> Response:
    """APIC XML response — the format CloudGuard's client unmarshals (regardless of the URL ext)."""
    return Response(aci.to_xml(objs), media_type="application/xml", status_code=status)


def _guard(dc, request: Request):
    if not aci.authorized(dc, apic_cookie=request.cookies.get("APIC-cookie", "")):
        return _xml(aci.forbidden_objs(), status=403)
    return None


def _login(dc, raw: bytes) -> Response:
    name, pwd = _creds(raw)
    if not aci.auth_ok(dc, name, pwd):
        return _xml(aci.forbidden_objs(), status=401)
    tok, objs = aci.login_objects(name)
    resp = _xml(objs)
    resp.set_cookie("APIC-cookie", tok)            # the controller echoes this back on every query
    return resp


def _refresh(dc) -> Response:
    tok, objs = aci.login_objects("")
    resp = _xml(objs)
    resp.set_cookie("APIC-cookie", tok)
    return resp


# --- apex routes (the path the controller actually hits — bare host + /api/...) -------------

@router.post("/api/aaaLogin.{fmt}")
@router.post("/api/aaaLogin")
async def aci_login_apex(request: Request, fmt: str = "", db: Session = Depends(get_db)):
    return _login(_apex_dc(db), await request.body())


# aaaRefresh is a GET in APIC (keeps the session token alive); POST kept defensively. A 405 here makes
# CloudGuard treat the session as dead → "Cannot execute request on a closed session" mid-scan.
@router.get("/api/aaaRefresh.{fmt}")
@router.get("/api/aaaRefresh")
@router.post("/api/aaaRefresh.{fmt}")
@router.post("/api/aaaRefresh")
def aci_refresh_apex(fmt: str = "", db: Session = Depends(get_db)):
    return _refresh(_apex_dc(db))


@router.get("/api/aaaLogout.{fmt}")
@router.get("/api/aaaLogout")
@router.post("/api/aaaLogout.{fmt}")
@router.post("/api/aaaLogout")
def aci_logout_apex(fmt: str = "", db: Session = Depends(get_db)):
    _apex_dc(db)
    return _xml([])                                # APIC logout → empty imdata


@router.get("/api/node/class/{cls}")
@router.get("/api/class/{cls}")
def aci_class_apex(cls: str, request: Request, db: Session = Depends(get_db)):
    dc = _apex_dc(db)
    return _guard(dc, request) or _xml(aci.class_objects(dc, cls))


@router.get("/api/node/mo/{rest:path}")
@router.get("/api/mo/{rest:path}")
def aci_mo_apex(rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _apex_dc(db)
    return _guard(dc, request) or _xml(aci.mo_subtree(dc, rest, dict(request.query_params)))


# --- token-path routes (direct testing of a specific datacenter) ----------------------------

@router.post("/aci/{token}/api/aaaLogin.{fmt}")
@router.post("/aci/{token}/api/aaaLogin")
async def aci_login_tok(token: str, request: Request, fmt: str = "", db: Session = Depends(get_db)):
    return _login(_dc(db, token), await request.body())


@router.get("/aci/{token}/api/aaaRefresh.{fmt}")
@router.get("/aci/{token}/api/aaaRefresh")
@router.post("/aci/{token}/api/aaaRefresh.{fmt}")
@router.post("/aci/{token}/api/aaaRefresh")
def aci_refresh_tok(token: str, fmt: str = "", db: Session = Depends(get_db)):
    return _refresh(_dc(db, token))


@router.get("/aci/{token}/api/aaaLogout.{fmt}")
@router.get("/aci/{token}/api/aaaLogout")
@router.post("/aci/{token}/api/aaaLogout.{fmt}")
@router.post("/aci/{token}/api/aaaLogout")
def aci_logout_tok(token: str, fmt: str = "", db: Session = Depends(get_db)):
    _dc(db, token)
    return _xml([])


@router.get("/aci/{token}/api/node/class/{cls}")
@router.get("/aci/{token}/api/class/{cls}")
def aci_class_tok(token: str, cls: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or _xml(aci.class_objects(dc, cls))


@router.get("/aci/{token}/api/node/mo/{rest:path}")
@router.get("/aci/{token}/api/mo/{rest:path}")
def aci_mo_tok(token: str, rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or _xml(aci.mo_subtree(dc, rest, dict(request.query_params)))


@router.get("/aci/{token}/api/{rest:path}")
def aci_other_tok(token: str, rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or _xml([])
