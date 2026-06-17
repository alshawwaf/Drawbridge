"""Mock VMware vCenter SOAP endpoint (vSphere Web Services) that CloudGuard Controller connects to.

Point the SmartConsole vCenter Data Center object's hostname at ``<portal>/vcenter/<token>/sdk``
with any read-only credentials. Every SOAP request/response is captured in the Activity log
(``ActivityLogMiddleware`` classifies ``/vcenter/*`` as a Data Center call and keeps the raw XML,
masking the password), so the exact PropertyCollector calls CloudGuard makes are visible and the
VM enumeration can be tuned to match.
"""
import base64
import re
import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter
from ..services import vsphere

router = APIRouter(tags=["vcenter-mock"])

_XML = "text/xml; charset=utf-8"


def _soap_response(method: str, xml: str, status: int) -> Response:
    """Wrap a SOAP reply; on Login, set the vmware_soap_session cookie real vCenter sets (later
    calls echo it back as the session credential)."""
    resp = Response(xml, media_type=_XML, status_code=status)
    if method == "Login" and status == 200:
        m = re.search(r"<key>(.*?)</key>", xml)
        if m:
            resp.set_cookie("vmware_soap_session", m.group(1), httponly=True)
    return resp


def _dc(db: Session, token: str) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.token == token, Datacenter.provider == "vcenter"))
    if dc is None:
        raise HTTPException(status_code=404, detail="vCenter datacenter not found")
    return dc


@router.get("/vcenter/{token}/sdk/vimServiceVersions.xml")
def vim_service_versions(token: str, db: Session = Depends(get_db)):
    """vSphere clients fetch this first to negotiate the API version."""
    _dc(db, token)
    return Response(vsphere.VIM_SERVICE_VERSIONS, media_type="text/xml")


@router.get("/vcenter/{token}/sdk")
def sdk_probe(token: str, db: Session = Depends(get_db)):
    # Some clients probe the endpoint with GET before POSTing SOAP.
    _dc(db, token)
    return Response(vsphere.VIM_SERVICE_VERSIONS, media_type="text/xml")


@router.post("/vcenter/{token}/sdk")
async def sdk_soap(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    body = await request.body()
    method = vsphere.parse_method(body)
    xml, status, _ = vsphere.handle(dc, method, body)
    return _soap_response(method, xml, status)


# --- Apex (root) routes ---------------------------------------------------------------------
# The SmartConsole vCenter "Hostname" field is a bare host (no path), and vCenter always connects
# to https://<host>/sdk. So we serve /sdk at the root and resolve the single vCenter datacenter
# (most-recently created). One vCenter mock per portal — the apex single-tenant model.
def _single_dc(db: Session) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.provider == "vcenter")
                   .order_by(Datacenter.created_at.desc()))
    if dc is None:
        raise HTTPException(status_code=404, detail="No vCenter datacenter configured")
    return dc


@router.get("/sdk/vimServiceVersions.xml")
def vim_versions_apex(db: Session = Depends(get_db)):
    _single_dc(db)
    return Response(vsphere.VIM_SERVICE_VERSIONS, media_type="text/xml")


@router.get("/sdk")
def sdk_probe_apex(db: Session = Depends(get_db)):
    _single_dc(db)
    return Response(vsphere.VIM_SERVICE_VERSIONS, media_type="text/xml")


@router.post("/sdk")
async def sdk_soap_apex(request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    body = await request.body()
    method = vsphere.parse_method(body)
    xml, status, _ = vsphere.handle(dc, method, body)
    return _soap_response(method, xml, status)


# --- vSphere Automation REST API (/rest/com/vmware/...) -------------------------------------
# CloudGuard authenticates to the REST API (session) in addition to SOAP, and reads vCenter tags
# through it. Served at the apex like /sdk. Responses use the vSphere 6.5-7.0 {"value": ...} shape.
def _basic_creds(request: Request) -> tuple[str, str]:
    h = request.headers.get("authorization", "")
    if h.lower().startswith("basic "):
        try:
            user, _, pwd = base64.b64decode(h[6:]).decode("utf-8").partition(":")
            return user, pwd
        except Exception:
            return "", ""
    return "", ""


def _rest_unauthenticated() -> JSONResponse:
    return JSONResponse({"type": "com.vmware.vapi.std.errors.unauthenticated",
                         "value": {"messages": [{"default_message": "Authentication required."}]}},
                        status_code=401)


@router.post("/rest/com/vmware/cis/session")
def rest_session_create(request: Request, db: Session = Depends(get_db)):
    dc = _single_dc(db)
    user, pwd = _basic_creds(request)
    if not vsphere.auth_ok(dc, user, pwd):
        return _rest_unauthenticated()
    return JSONResponse({"value": uuid.uuid4().hex})


@router.delete("/rest/com/vmware/cis/session")
def rest_session_delete(db: Session = Depends(get_db)):
    _single_dc(db)
    return Response(status_code=200)


# vCenter tags (vSphere tagging service). CloudGuard reads these so policy can target VMs by tag —
# the primary reason to add a vCenter Data Center object. Derived from the VMs' tags.
_TAG = "/rest/com/vmware/cis/tagging"


@router.get(_TAG + "/category")
def rest_tag_categories(db: Session = Depends(get_db)):
    return JSONResponse({"value": [vsphere.tag_catalog(_single_dc(db))["category"]["id"]]})


@router.get(_TAG + "/category/{cid}")
def rest_tag_category(cid: str, db: Session = Depends(get_db)):
    return JSONResponse({"value": vsphere.tag_catalog(_single_dc(db))["category"]})


@router.get(_TAG + "/tag")
def rest_tags(db: Session = Depends(get_db)):
    return JSONResponse({"value": [t["id"] for t in vsphere.tag_catalog(_single_dc(db))["tags"]]})


@router.get(_TAG + "/tag/{tid}")
def rest_tag(tid: str, db: Session = Depends(get_db)):
    tid = tid[3:] if tid.startswith("id:") else tid
    tags = vsphere.tag_catalog(_single_dc(db))["tags"]
    return JSONResponse({"value": next((t for t in tags if t["id"] == tid), {})})


@router.api_route(_TAG + "/tag-association/{tid}", methods=["GET", "POST"])
def rest_tag_association(tid: str, db: Session = Depends(get_db)):
    tid = tid[3:] if tid.startswith("id:") else tid
    members = vsphere.tag_catalog(_single_dc(db))["assoc"].get(tid, [])
    return JSONResponse({"value": [{"id": m, "type": "VirtualMachine"} for m in members]})


# Any other REST call CloudGuard makes — return an empty value-list so the import doesn't 404-stall.
# Each call is in the Activity log so unmodeled endpoints can be filled in from the real traffic.
@router.api_route("/rest/{rest:path}", methods=["GET", "POST"])
def rest_other(rest: str, db: Session = Depends(get_db)):
    _single_dc(db)
    return JSONResponse({"value": []})
