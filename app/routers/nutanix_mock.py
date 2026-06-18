"""Mock Nutanix Prism (REST) that CloudGuard Controller R82.10 connects to.

CloudGuard authenticates with HTTP **Basic** auth and probes **Prism v4** first
(``GET /api/vmm/v4.1/ahv/config/vms?$limit=1``), falling back to **v3** (``POST /api/nutanix/v3/...``).
Both are served at the **root** (apex single-tenant, most-recent nutanix DC). The Prism Central port is
9440; since the portal answers on 443 the admin enters ``<host>:443``. Token routes
(``/nutanix/<token>/...``) are kept for direct testing. Every call is in the Activity log.

The ``/api/nutanix/``, ``/api/vmm/`` and ``/api/prism/`` prefixes are unique (no overlap with the
NSX-T/K8s/ACI apex paths), so this router has no ordering constraints.
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter
from ..services import nutanix

router = APIRouter(tags=["nutanix-mock"])


def _nutanix_dc(db: Session) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.provider == "nutanix")
                   .order_by(Datacenter.created_at.desc()))
    if dc is None:
        raise HTTPException(status_code=404, detail="No Nutanix datacenter configured")
    return dc


def _dc(db: Session, token: str) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.token == token, Datacenter.provider == "nutanix"))
    if dc is None:
        raise HTTPException(status_code=404, detail="Nutanix datacenter not found")
    return dc


def _guard(dc, request: Request):
    if not nutanix.authorized(dc, request.headers.get("authorization", "")):
        return JSONResponse(nutanix.unauthorized(), status_code=401)
    return None


async def _body(request: Request) -> dict:
    try:
        return await request.json()
    except Exception:
        return {}


# --- apex (root) routes — v3 (POST) + v4 (GET) ----------------------------------------------

@router.get("/api/nutanix/v3/users/me")
def users_me_apex(request: Request, db: Session = Depends(get_db)):
    dc = _nutanix_dc(db)
    return _guard(dc, request) or nutanix.users_me()


@router.post("/api/nutanix/v3/vms/list")
def vms_list_apex(request: Request, db: Session = Depends(get_db)):
    dc = _nutanix_dc(db)
    return _guard(dc, request) or nutanix.vms_list_v3(dc)


@router.post("/api/nutanix/v3/categories/list")
def categories_list_apex(request: Request, db: Session = Depends(get_db)):
    dc = _nutanix_dc(db)
    return _guard(dc, request) or nutanix.categories_list_v3(dc)


@router.post("/api/nutanix/v3/categories/{name}/list")
def category_values_apex(name: str, request: Request, db: Session = Depends(get_db)):
    dc = _nutanix_dc(db)
    return _guard(dc, request) or nutanix.category_values_v3(dc, name)


@router.post("/api/nutanix/v3/category/query")
async def category_query_apex(request: Request, db: Session = Depends(get_db)):
    dc = _nutanix_dc(db)
    return _guard(dc, request) or nutanix.category_query_v3(dc, await _body(request))


@router.get("/api/vmm/v4.1/ahv/config/vms")
def vms_v4_apex(request: Request, db: Session = Depends(get_db)):
    dc = _nutanix_dc(db)                               # also serves the ?$limit=1 test-connection probe
    return _guard(dc, request) or nutanix.vms_list_v4(dc)


@router.get("/api/prism/v4.1/config/categories")
def categories_v4_apex(request: Request, db: Session = Depends(get_db)):
    dc = _nutanix_dc(db)
    return _guard(dc, request) or nutanix.categories_list_v4(dc)


# Any other Prism v3 GET/POST CloudGuard probes returns an empty v3 list (unique /api/nutanix/ prefix,
# so this can't shadow another provider). Each call is still in the Activity log to model later.
@router.api_route("/api/nutanix/{rest:path}", methods=["GET", "POST"])
def nutanix_other_apex(rest: str, request: Request, db: Session = Depends(get_db)):
    dc = _nutanix_dc(db)
    return _guard(dc, request) or nutanix._v3_envelope("vm", [])


# --- token-prefixed routes (direct testing of a specific datacenter) ------------------------

@router.get("/nutanix/{token}/api/nutanix/v3/users/me")
def users_me_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nutanix.users_me()


@router.post("/nutanix/{token}/api/nutanix/v3/vms/list")
def vms_list_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nutanix.vms_list_v3(dc)


@router.post("/nutanix/{token}/api/nutanix/v3/categories/list")
def categories_list_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nutanix.categories_list_v3(dc)


@router.post("/nutanix/{token}/api/nutanix/v3/category/query")
async def category_query_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nutanix.category_query_v3(dc, await _body(request))


@router.get("/nutanix/{token}/api/vmm/v4.1/ahv/config/vms")
def vms_v4_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nutanix.vms_list_v4(dc)


@router.get("/nutanix/{token}/api/prism/v4.1/config/categories")
def categories_v4_tok(token: str, request: Request, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    return _guard(dc, request) or nutanix.categories_list_v4(dc)
