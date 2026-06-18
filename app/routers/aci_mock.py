"""Mock Cisco ACI / APIC (REST) that CloudGuard Controller R82.10 connects to.

The SmartConsole ACI object's *URLs* field takes a full URL, so the admin enters
``https://<portal>/aci/<token>`` and the controller appends ``/api/aaaLogin.xml`` and
``/api/node/class/<class>.xml`` — served here under the token path (path-based, many ACI mocks per
portal). **CloudGuard's APIC client unmarshals XML**, so responses default to APIC XML
(``<imdata><fvTenant .../></imdata>``); the ``.json`` form is also served for shell testing. Login
returns a token echoed back as the ``APIC-cookie``. Every call is in the Activity log (``/aci/*``).
"""
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
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


def _fmt(s: str) -> str:
    """Response format from the request's extension — XML is the default (CloudGuard's APIC client)."""
    return "json" if (s or "").endswith(".json") else "xml"


def _render(objs: list, fmt: str, status: int = 200) -> Response:
    if fmt == "json":
        return JSONResponse(aci.imdata(objs), status_code=status)
    return Response(aci.to_xml(objs), media_type="application/xml", status_code=status)


def _guard(dc, request: Request, fmt: str):
    """APIC error envelope (in the requested format) unless the request carries our APIC-cookie."""
    if not aci.authorized(dc, apic_cookie=request.cookies.get("APIC-cookie", "")):
        return _render(aci.forbidden_objs(), fmt, status=403)
    return None


@router.post("/aci/{token}/api/aaaLogin.{fmt}")
@router.post("/aci/{token}/api/aaaLogin")
async def aci_login(token: str, request: Request, fmt: str = "xml", db: Session = Depends(get_db)):
    dc = _dc(db, token)
    name, pwd = _creds(await request.body())
    if not aci.auth_ok(dc, name, pwd):
        return _render(aci.forbidden_objs(), fmt, status=401)
    tok, objs = aci.login_objects(name)
    resp = _render(objs, fmt)
    resp.set_cookie("APIC-cookie", tok)            # the controller echoes this back on every query
    return resp


@router.post("/aci/{token}/api/aaaRefresh.{fmt}")
@router.post("/aci/{token}/api/aaaRefresh")
def aci_refresh(token: str, fmt: str = "xml", db: Session = Depends(get_db)):
    _dc(db, token)
    tok, objs = aci.login_objects("")
    resp = _render(objs, fmt)
    resp.set_cookie("APIC-cookie", tok)
    return resp


@router.get("/aci/{token}/api/node/class/{cls}")
@router.get("/aci/{token}/api/class/{cls}")
def aci_class(token: str, cls: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request, _fmt(cls)) or _render(aci.class_objects(dc, cls), _fmt(cls))


# MO (managed-object) queries by DN and any other /api/... path → empty imdata (so enumeration
# completes); each is still logged so an unmodeled query can be implemented after the first trace.
@router.get("/aci/{token}/api/node/mo/{rest:path}")
@router.get("/aci/{token}/api/mo/{rest:path}")
@router.get("/aci/{token}/api/{rest:path}")
def aci_other(token: str, rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request, _fmt(rest)) or _render([], _fmt(rest))
