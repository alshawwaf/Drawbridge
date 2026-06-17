"""Mock VMware NSX-T Manager (Policy Mode REST) that CloudGuard Controller connects to.

Point the SmartConsole NSX-T Data Center object's hostname at ``<portal>/nsxt/<token>``; the
controller appends ``/api/session/create`` and ``/policy/api/v1/...`` which this router serves
from the datacenter's simulated inventory. Every call is captured in the Activity log
(``/nsxt/*`` classified as a Data Center call, password masked), so the exact Policy-Mode calls
CloudGuard makes are visible and the responses can be tuned to match.
"""
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter
from ..services import nsxt

router = APIRouter(tags=["nsxt-mock"])


def _dc(db: Session, token: str) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.token == token, Datacenter.provider == "nsxt"))
    if dc is None:
        raise HTTPException(status_code=404, detail="NSX-T datacenter not found")
    return dc


def _guard(dc, request: Request):
    """Return a 403 response if the request isn't authorized, else None."""
    if not nsxt.authorized(dc, authorization=request.headers.get("authorization", ""),
                           jsessionid=request.cookies.get("JSESSIONID", "")):
        return JSONResponse(nsxt.forbidden(), status_code=403)
    return None


@router.post("/nsxt/{token}/api/session/create")
def session_create(token: str, request: Request, j_username: str = Form(""),
                   j_password: str = Form(""), db: Session = Depends(get_db)):
    dc = _dc(db, token)
    if not nsxt.auth_ok(dc, j_username, j_password):
        return JSONResponse(nsxt.forbidden(), status_code=403)
    resp = Response(status_code=200)
    resp.set_cookie("JSESSIONID", uuid.uuid4().hex)
    resp.headers["X-XSRF-TOKEN"] = uuid.uuid4().hex
    return resp


@router.post("/nsxt/{token}/api/session/destroy")
def session_destroy(token: str, db: Session = Depends(get_db)):
    _dc(db, token)
    return Response(status_code=200)


@router.get("/nsxt/{token}/policy/api/v1/infra/domains/default/groups")
def list_groups(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.groups(dc)


@router.get("/nsxt/{token}/policy/api/v1/infra/domains/default/groups/{group_id}/members/virtual-machines")
def group_members(token: str, group_id: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.group_members(dc, group_id)


@router.get("/nsxt/{token}/policy/api/v1/infra/realized-state/virtual-machines")
def realized_vms(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.virtual_machines(dc)


@router.get("/nsxt/{token}/api/v1/fabric/vifs")
def fabric_vifs(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.vifs(dc)


# Declared LAST: any other Policy/Manager GET collection CloudGuard probes returns an empty
# NSX-T ListResult instead of a 404, so enumeration completes. Each call is still in the
# Activity log, so an unmodeled endpoint can be implemented later.
@router.get("/nsxt/{token}/policy/api/v1/{rest:path}")
@router.get("/nsxt/{token}/api/v1/{rest:path}")
def nsxt_other_collection(token: str, rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.list_result([])
