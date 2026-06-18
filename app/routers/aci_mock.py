"""Mock Cisco ACI / APIC (REST) that CloudGuard Controller R82.10 connects to.

The SmartConsole ACI object's *URLs* field takes a full URL (scheme required), so the admin enters
``https://<portal>/aci/<token>`` and the controller appends ``/api/aaaLogin.json`` and
``/api/node/class/<class>.json`` — this router serves them under the token path (path-based, so a
portal can host many ACI mocks). Login returns a token that the controller sends back as the
``APIC-cookie``. Every call is captured in the Activity log (``/aci/*`` classified as a Data Center
call), so the exact class queries CloudGuard makes are visible and the responses tuned to match.
"""
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter
from ..services import aci

router = APIRouter(tags=["aci-mock"])


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


def _guard(dc, request: Request):
    """403 (APIC error envelope) unless the request carries the APIC-cookie we issued at login."""
    if not aci.authorized(dc, apic_cookie=request.cookies.get("APIC-cookie", "")):
        return JSONResponse(aci.forbidden(), status_code=403)
    return None


@router.post("/aci/{token}/api/aaaLogin.json")
async def aci_login(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    name, pwd = _creds(await request.body())
    if not aci.auth_ok(dc, name, pwd):
        return JSONResponse(aci.forbidden(), status_code=401)
    tok, body = aci.login_response(name)
    resp = JSONResponse(body)
    resp.set_cookie("APIC-cookie", tok)            # the controller echoes this back on every query
    return resp


@router.post("/aci/{token}/api/aaaRefresh.json")
def aci_refresh(token: str, db: Session = Depends(get_db)):
    _dc(db, token)
    tok, body = aci.login_response("")
    resp = JSONResponse(body)
    resp.set_cookie("APIC-cookie", tok)
    return resp


@router.get("/aci/{token}/api/node/class/{cls}")
def aci_class_node(token: str, cls: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or aci.class_query(dc, cls)


@router.get("/aci/{token}/api/class/{cls}")
def aci_class(token: str, cls: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or aci.class_query(dc, cls)


# MO (managed-object) queries by DN and any other /api/... path → empty imdata (so enumeration
# completes); each is still logged so an unmodeled query can be implemented after the first trace.
@router.get("/aci/{token}/api/node/mo/{rest:path}")
@router.get("/aci/{token}/api/mo/{rest:path}")
@router.get("/aci/{token}/api/{rest:path}")
def aci_other(token: str, rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or aci.imdata([])
