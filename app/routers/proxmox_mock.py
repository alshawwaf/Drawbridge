"""Mock Proxmox VE (``/api2/json`` REST) that CloudGuard Controller R82.10 connects to.

The SmartConsole Proxmox object's *Hostname* is a bare host with an optional port (Proxmox default
**8006**). Our portal answers on **443**, so the admin enters ``<host>:443`` and the controller calls
``https://<host>:443/api2/json/...`` which this router serves at the **root** (apex single-tenant,
resolving the most-recently created Proxmox datacenter). Auth is a Proxmox **API token** sent as
``Authorization: PVEAPIToken=<user>@<realm>!<tokenid>=<secret>``.

Token-prefixed routes (``/proxmox/<token>/api2/json/...``) are kept for direct testing. Every call is
captured in the Activity log (``/api2/json`` + ``/proxmox/`` classified as a Data Center call), so the
exact endpoints CloudGuard hits are visible and the responses can be tuned to match.
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter
from ..services import proxmox

router = APIRouter(tags=["proxmox-mock"])


def _proxmox_dc(db: Session) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.provider == "proxmox")
                   .order_by(Datacenter.created_at.desc()))
    if dc is None:
        raise HTTPException(status_code=404, detail="No Proxmox datacenter configured")
    return dc


def _dc(db: Session, token: str) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.token == token, Datacenter.provider == "proxmox"))
    if dc is None:
        raise HTTPException(status_code=404, detail="Proxmox datacenter not found")
    return dc


def _guard(dc, request: Request):
    """Return a 401 response if the API token isn't valid, else None."""
    if not proxmox.authorized(dc, request.headers.get("authorization", "")):
        return JSONResponse(proxmox.unauthorized(), status_code=401)
    return None


# --- apex (root) routes — the path CloudGuard actually uses (host:443/api2/json/...) -------

@router.post("/api2/json/access/ticket")
def access_ticket(username: str = Form(""), password: str = Form("")):
    return proxmox.ticket(username)  # password/ticket flow — defensive; CloudGuard uses a token


@router.get("/api2/json/version")
def version_apex(request: Request, db: Session = Depends(get_db)):
    dc = _proxmox_dc(db)
    return _guard(dc, request) or proxmox.version()


@router.get("/api2/json/cluster/resources")
def cluster_resources_apex(request: Request, type: str = "", db: Session = Depends(get_db)):
    dc = _proxmox_dc(db)
    return _guard(dc, request) or proxmox.cluster_resources(dc, type)


@router.get("/api2/json/nodes")
def nodes_apex(request: Request, db: Session = Depends(get_db)):
    dc = _proxmox_dc(db)
    return _guard(dc, request) or proxmox.nodes(dc)


@router.get("/api2/json/nodes/{node}/qemu")
def node_qemu_apex(node: str, request: Request, db: Session = Depends(get_db)):
    dc = _proxmox_dc(db)
    return _guard(dc, request) or proxmox.node_qemu(dc, node)


@router.get("/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")
def agent_ifaces_apex(node: str, vmid: int, request: Request, db: Session = Depends(get_db)):
    dc = _proxmox_dc(db)
    return _guard(dc, request) or proxmox.agent_interfaces(dc, vmid)


@router.get("/api2/json/nodes/{node}/qemu/{vmid}/config")
def qemu_config_apex(node: str, vmid: int, request: Request, db: Session = Depends(get_db)):
    dc = _proxmox_dc(db)
    return _guard(dc, request) or proxmox.qemu_config(dc, vmid)


@router.get("/api2/json/pools")
def pools_apex(request: Request, db: Session = Depends(get_db)):
    dc = _proxmox_dc(db)
    return _guard(dc, request) or proxmox.pools(dc)


# Declared LAST: any other /api2/json GET CloudGuard probes returns an empty Proxmox list instead of
# a 404, so enumeration completes. Each call is still in the Activity log to model later.
@router.get("/api2/json/{rest:path}")
def proxmox_other_apex(rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _proxmox_dc(db)
    return _guard(dc, request) or proxmox.data([])


# --- token-prefixed routes (direct testing of a specific datacenter) ------------------------

@router.post("/proxmox/{token}/api2/json/access/ticket")
def access_ticket_tok(token: str, username: str = Form(""), db: Session = Depends(get_db)):
    _dc(db, token)
    return proxmox.ticket(username)


@router.get("/proxmox/{token}/api2/json/version")
def version_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or proxmox.version()


@router.get("/proxmox/{token}/api2/json/cluster/resources")
def cluster_resources_tok(token: str, request: Request, type: str = "", db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or proxmox.cluster_resources(dc, type)


@router.get("/proxmox/{token}/api2/json/nodes")
def nodes_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or proxmox.nodes(dc)


@router.get("/proxmox/{token}/api2/json/nodes/{node}/qemu")
def node_qemu_tok(token: str, node: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or proxmox.node_qemu(dc, node)


@router.get("/proxmox/{token}/api2/json/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")
def agent_ifaces_tok(token: str, node: str, vmid: int, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or proxmox.agent_interfaces(dc, vmid)


@router.get("/proxmox/{token}/api2/json/{rest:path}")
def proxmox_other_tok(token: str, rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or proxmox.data([])
