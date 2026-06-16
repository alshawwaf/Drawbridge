"""Mock VMware vCenter SOAP endpoint (vSphere Web Services) that CloudGuard Controller connects to.

Point the SmartConsole vCenter Data Center object's hostname at ``<portal>/vcenter/<token>/sdk``
with any read-only credentials. Every SOAP request/response is captured in the Activity log
(``ActivityLogMiddleware`` classifies ``/vcenter/*`` as a Data Center call and keeps the raw XML,
masking the password), so the exact PropertyCollector calls CloudGuard makes are visible and the
VM enumeration can be tuned to match.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter
from ..services import vsphere

router = APIRouter(tags=["vcenter-mock"])

_XML = "text/xml; charset=utf-8"


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
    return Response(xml, media_type=_XML, status_code=status)
