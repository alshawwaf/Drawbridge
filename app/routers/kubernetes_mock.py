"""Mock Kubernetes kube-apiserver (REST) that CloudGuard Controller R82.10 connects to.

CloudGuard authenticates with a service-account **bearer token** and calls ``GET /api`` then
``GET /api/v1/{nodes,pods,services,endpoints}``. We serve those at the **root** (apex single-tenant,
resolving the most-recently created Kubernetes datacenter). The kube-apiserver default port is 6443, but
the connector parses this field with ``new URL()`` — so the admin enters the full URL ``https://<host>``
(scheme required, **no** port; a bare ``host:443`` fails with “unknown protocol”). It then connects on
443 (the portal's port). Token routes (``/k8s/<token>/...``) are kept for direct testing. Every call is
in the Activity log.

**Routing:** ``/api/v1/...`` is shared with the NSX-T family mock (which has an ``/api/v1/{rest}``
catch-all). The Kubernetes paths (``/api/v1/nodes|pods|services|endpoints`` and ``GET /api``) are
explicit, and this router is registered **before** ``nsxt_mock`` so they match first; NSX-T's own
paths (``/api/session``, ``/api/v1/fabric/vifs``, the catch-all) fall through to it.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter
from ..services import kubernetes as k8s

router = APIRouter(tags=["kubernetes-mock"])


def _k8s_dc(db: Session) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.provider == "kubernetes")
                   .order_by(Datacenter.created_at.desc()))
    if dc is None:
        raise HTTPException(status_code=404, detail="No Kubernetes datacenter configured")
    return dc


def _dc(db: Session, token: str) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.token == token,
                                            Datacenter.provider == "kubernetes"))
    if dc is None:
        raise HTTPException(status_code=404, detail="Kubernetes datacenter not found")
    return dc


def _guard(dc, request: Request):
    """Return a 401 Status if the bearer token isn't valid, else None."""
    if not k8s.authorized(dc, request.headers.get("authorization", "")):
        return JSONResponse(k8s.unauthorized(), status_code=401)
    return None


# --- apex (root) routes — the path CloudGuard actually uses (host:443/api/...) --------------

@router.get("/api")
def api_versions_apex(db: Session = Depends(get_db)):
    _k8s_dc(db)                                        # 404 if no k8s DC; version discovery is open
    return k8s.api_versions()


@router.get("/api/v1/nodes")
def nodes_apex(request: Request, db: Session = Depends(get_db)):
    dc = _k8s_dc(db)
    return _guard(dc, request) or k8s.nodes(dc)


@router.get("/api/v1/pods")
def pods_apex(request: Request, db: Session = Depends(get_db)):
    dc = _k8s_dc(db)
    return _guard(dc, request) or k8s.pods(dc)


@router.get("/api/v1/services")
def services_apex(request: Request, db: Session = Depends(get_db)):
    dc = _k8s_dc(db)
    return _guard(dc, request) or k8s.services(dc)


@router.get("/api/v1/endpoints")
def endpoints_apex(request: Request, db: Session = Depends(get_db)):
    dc = _k8s_dc(db)
    return _guard(dc, request) or k8s.endpoints(dc)


# --- token-prefixed routes (direct testing of a specific datacenter) ------------------------

@router.get("/k8s/{token}/api")
def api_versions_tok(token: str, db: Session = Depends(get_db)):
    _dc(db, token)
    return k8s.api_versions()


@router.get("/k8s/{token}/api/v1/nodes")
def nodes_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or k8s.nodes(dc)


@router.get("/k8s/{token}/api/v1/pods")
def pods_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or k8s.pods(dc)


@router.get("/k8s/{token}/api/v1/services")
def services_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or k8s.services(dc)


@router.get("/k8s/{token}/api/v1/endpoints")
def endpoints_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or k8s.endpoints(dc)
