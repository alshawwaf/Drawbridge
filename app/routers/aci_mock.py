"""Mock Cisco ACI / APIC (REST) that CloudGuard Controller R82.10 connects to.

The SmartConsole ACI object's *URLs* field takes a full URL, so the admin enters
``https://<portal>/aci/<token>`` and the controller appends ``/api/aaaLogin`` and
``/api/node/class/<class>`` (with or without a ``.xml``/``.json`` extension) — served here under the
token path (path-based, many ACI mocks per portal).

**CloudGuard's APIC client unmarshals XML unconditionally** (`apic_service.jar` → JAXB/SAX; JSON makes
it fail with "Content is not allowed in prolog"), so this mock answers **APIC XML for every
extension** — ``<imdata totalCount="N"><fvTenant .../>…</imdata>``. Login returns a token echoed back
as the ``APIC-cookie``. Every call is captured in the Activity log (``/aci/*``).
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


# aaaLogin / aaaRefresh — matched with or without a .xml/.json extension; always answered in XML.
@router.post("/aci/{token}/api/aaaLogin.{fmt}")
@router.post("/aci/{token}/api/aaaLogin")
async def aci_login(token: str, request: Request, fmt: str = "", db: Session = Depends(get_db)):
    dc = _dc(db, token)
    name, pwd = _creds(await request.body())
    if not aci.auth_ok(dc, name, pwd):
        return _xml(aci.forbidden_objs(), status=401)
    tok, objs = aci.login_objects(name)
    resp = _xml(objs)
    resp.set_cookie("APIC-cookie", tok)            # the controller echoes this back on every query
    return resp


@router.post("/aci/{token}/api/aaaRefresh.{fmt}")
@router.post("/aci/{token}/api/aaaRefresh")
def aci_refresh(token: str, fmt: str = "", db: Session = Depends(get_db)):
    _dc(db, token)
    tok, objs = aci.login_objects("")
    resp = _xml(objs)
    resp.set_cookie("APIC-cookie", tok)
    return resp


@router.get("/aci/{token}/api/node/class/{cls}")
@router.get("/aci/{token}/api/class/{cls}")
def aci_class(token: str, cls: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or _xml(aci.class_objects(dc, cls))


# MO (managed-object) queries by DN and any other /api/... path → empty imdata (so enumeration
# completes); each is still logged so an unmodeled query can be implemented after the first trace.
@router.get("/aci/{token}/api/node/mo/{rest:path}")
@router.get("/aci/{token}/api/mo/{rest:path}")
@router.get("/aci/{token}/api/{rest:path}")
def aci_other(token: str, rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or _xml([])
