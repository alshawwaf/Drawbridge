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


@router.get("/nsxt/{token}/policy/api/v1/infra/domains")
def list_domains(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.domains()


@router.get("/nsxt/{token}/policy/api/v1/infra/domains/default/groups")
def list_groups(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.groups(dc)


@router.get("/nsxt/{token}/policy/api/v1/infra/domains/default/groups/{group_id}/members/virtual-machines")
def group_members(token: str, group_id: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.group_members(dc, group_id)


@router.get("/nsxt/{token}/policy/api/v1/infra/domains/default/groups/{group_id}/members/ip-addresses")
def group_member_ips(token: str, group_id: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.group_member_ips(dc, group_id)


@router.get("/nsxt/{token}/policy/api/v1/infra/realized-state/enforcement-points/default/vifs")
def realized_vifs(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nsxt.vifs(dc)


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


# --- Apex (root) routes ---------------------------------------------------------------------
# The SmartConsole NSX-T "Hostname" field is a bare host; the controller calls /api/... and
# /policy/... at the root. So we serve those at the root and resolve the single NSX-T datacenter
# (most-recently created). Explicit paths are declared before the {rest:path} catch-alls.
def _single_dc(db: Session) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.provider == "nsxt")
                   .order_by(Datacenter.created_at.desc()))
    if dc is None:
        raise HTTPException(status_code=404, detail="No NSX-T datacenter configured")
    return dc


def _global_dc(db: Session) -> Datacenter:
    """Most-recent Global NSX-T (Global Manager) datacenter."""
    dc = db.scalar(select(Datacenter).where(Datacenter.provider == "globalnsxt")
                   .order_by(Datacenter.created_at.desc()))
    if dc is None:
        raise HTTPException(status_code=404, detail="No Global NSX-T datacenter configured")
    return dc


def _family_dc(db: Session) -> Datacenter:
    """Most-recent NSX-T *family* datacenter (Local or Global Manager). Used for the endpoints both
    share — the session handshake (/api/session) and the Manager API (/api/v1/...) — since they're
    distinguished only by the later policy path (/policy/... = LM, /global-manager/... = GM)."""
    dc = db.scalar(select(Datacenter).where(Datacenter.provider.in_(("nsxt", "globalnsxt")))
                   .order_by(Datacenter.created_at.desc()))
    if dc is None:
        raise HTTPException(status_code=404, detail="No NSX-T datacenter configured")
    return dc


@router.post("/api/session/create")
def session_create_apex(request: Request, j_username: str = Form(""), j_password: str = Form(""),
                        db: Session = Depends(get_db)):
    dc = _family_dc(db)  # shared by NSX-T (LM) and Global NSX-T (GM)
    if not nsxt.auth_ok(dc, j_username, j_password):
        return JSONResponse(nsxt.forbidden(), status_code=403)
    resp = Response(status_code=200)
    resp.set_cookie("JSESSIONID", uuid.uuid4().hex)
    resp.headers["X-XSRF-TOKEN"] = uuid.uuid4().hex
    return resp


@router.post("/api/session/destroy")
def session_destroy_apex(db: Session = Depends(get_db)):
    _family_dc(db)
    return Response(status_code=200)


@router.get("/policy/api/v1/infra/domains")
def list_domains_apex(request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    return _guard(dc, request) or nsxt.domains()


@router.get("/policy/api/v1/infra/domains/default/groups")
def list_groups_apex(request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    return _guard(dc, request) or nsxt.groups(dc)


@router.get("/policy/api/v1/infra/domains/default/groups/{group_id}/members/virtual-machines")
def group_members_apex(group_id: str, request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    return _guard(dc, request) or nsxt.group_members(dc, group_id)


@router.get("/policy/api/v1/infra/domains/default/groups/{group_id}/members/ip-addresses")
def group_member_ips_apex(group_id: str, request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    return _guard(dc, request) or nsxt.group_member_ips(dc, group_id)


@router.get("/policy/api/v1/infra/realized-state/enforcement-points/default/vifs")
def realized_vifs_apex(request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    return _guard(dc, request) or nsxt.vifs(dc)


@router.get("/policy/api/v1/infra/realized-state/virtual-machines")
def realized_vms_apex(request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    return _guard(dc, request) or nsxt.virtual_machines(dc)


@router.get("/api/v1/fabric/vifs")
def fabric_vifs_apex(request: Request, db: Session = Depends(get_db)):
    dc = _family_dc(db)  # the Manager (/api/v1) API is shared by LM and GM
    return _guard(dc, request) or nsxt.vifs(dc)


@router.get("/policy/api/v1/{rest:path}")
def nsxt_other_apex(rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    return _guard(dc, request) or nsxt.list_result([])


@router.get("/api/v1/{rest:path}")
def manager_other_apex(rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _family_dc(db)
    return _guard(dc, request) or nsxt.list_result([])


# --- Global NSX-T (Global Manager / Federation) ---------------------------------------------
# Same handshake (/api/session) and Manager API (/api/v1) as NSX-T, but objects live under the GM
# policy path /global-manager/api/v1/global-infra/... (vs the LM's /policy/api/v1/infra/...).
# Resolves the most-recent globalnsxt datacenter. Imports: NS Groups (-> member VMs), VMs, Tags;
# Regions land via the catch-all until the first real-CloudGuard trace shows their exact shape.
_GM = "/global-manager/api/v1/global-infra"


@router.get(_GM + "/sites")
def gm_sites_apex(request: Request, db: Session = Depends(get_db)):
    """Federation Locations → CloudGuard Regions. Must return a real site (not the catch-all's empty
    list) or the Region stays an empty placeholder and the global NS Groups never nest under it."""
    dc = _global_dc(db)
    return _guard(dc, request) or nsxt.sites(dc)


@router.get(_GM + "/domains")
def gm_domains_apex(request: Request, db: Session = Depends(get_db)):
    dc = _global_dc(db)
    return _guard(dc, request) or nsxt.domains(infra="global-infra")


@router.get(_GM + "/domains/default/groups")
def gm_groups_apex(request: Request, db: Session = Depends(get_db)):
    dc = _global_dc(db)
    return _guard(dc, request) or nsxt.groups(dc, infra="global-infra")


@router.get(_GM + "/domains/default/groups/{group_id}/members/virtual-machines")
def gm_group_members_apex(group_id: str, request: Request, db: Session = Depends(get_db)):
    dc = _global_dc(db)
    return _guard(dc, request) or nsxt.group_members(dc, group_id)


@router.get(_GM + "/domains/default/groups/{group_id}/members/ip-addresses")
def gm_group_member_ips_apex(group_id: str, request: Request, db: Session = Depends(get_db)):
    dc = _global_dc(db)
    return _guard(dc, request) or nsxt.group_member_ips(dc, group_id)


@router.get(_GM + "/realized-state/enforcement-points/default/vifs")
def gm_realized_vifs_apex(request: Request, db: Session = Depends(get_db)):
    dc = _global_dc(db)
    return _guard(dc, request) or nsxt.vifs(dc)


@router.get(_GM + "/realized-state/virtual-machines")
def gm_realized_vms_apex(request: Request, db: Session = Depends(get_db)):
    dc = _global_dc(db)
    return _guard(dc, request) or nsxt.virtual_machines(dc)


@router.get("/global-manager/api/v1/{rest:path}")
def gm_other_apex(rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _global_dc(db)
    return _guard(dc, request) or nsxt.list_result([])
