"""App-wide Activity log: live, filterable view of integration traffic with request/response."""
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import and_, delete, func, or_, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ActivityLog
from ..security import get_user_or_none
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)

KIND_LABELS = {"feed_poll": "Feed poll", "gaia_mock": "Mock Gaia API", "layer_apply": "Layer apply",
               "gateway_read": "Gateway read", "datacenter": "Data Center", "api": "API", "ui": "Page view"}

# Data Center sub-filter: which path fragments identify each provider's traffic, so the user can
# narrow the "Data Center" kind to one provider when troubleshooting (vCenter vs NSX-T vs Proxmox…).
# (The shared NSX-T-family /api/session + /api/v1 calls aren't provider-specific, so they only show
# under the unfiltered Data Center view.)
PROVIDER_PATHS = {
    "vcenter": ["/sdk", "/rest/", "/vcenter/"],
    "nsxt": ["/policy/", "/nsxt/"],
    "globalnsxt": ["/global-manager/"],
    "openstack": ["/openstack/"],
    "proxmox": ["/api2/json", "/proxmox/"],
    "aci": ["/aci/", "/api/aaaLogin", "/api/aaaRefresh", "/api/aaaLogout",
            "/api/node/", "/api/class/", "/api/mo/"],
    "kubernetes": ["/k8s/", "/api/v1/nodes", "/api/v1/pods", "/api/v1/services", "/api/v1/endpoints"],
    "nutanix": ["/nutanix/", "/api/nutanix/", "/api/vmm/", "/api/prism/"],
}
PROVIDER_LABELS = {"vcenter": "vCenter", "nsxt": "NSX-T", "globalnsxt": "Global NSX-T",
                   "openstack": "OpenStack", "proxmox": "Proxmox", "aci": "Cisco ACI",
                   "kubernetes": "Kubernetes", "nutanix": "Nutanix"}

PAGE_SIZES = [10, 25, 50, 100]
DEFAULT_PAGE_SIZE = 10


def _filter_conds(sel_kinds: list[str], dc: str, q: str) -> list:
    """SQL conditions for the row/count queries. A specific ``dc`` provider narrows to that provider's
    paths (and overrides the kind checkboxes); otherwise the checked kinds apply. ``q`` is a free-text
    AND-match across path, summary, and source IP."""
    conds = []
    if dc in PROVIDER_PATHS:
        conds.append(or_(*[ActivityLog.path.like(f"%{p}%") for p in PROVIDER_PATHS[dc]]))
    elif sel_kinds:
        conds.append(ActivityLog.kind.in_(sel_kinds))
    q = (q or "").strip()
    if q:
        like = f"%{q}%"
        conds.append(or_(ActivityLog.path.like(like), ActivityLog.summary.like(like),
                         ActivityLog.source_ip.like(like)))
    return conds


def _clean_kinds(kinds: list[str]) -> list[str]:
    """Keep only valid kinds, in the canonical KIND_LABELS order (deduped)."""
    chosen = set(kinds or [])
    return [k for k in KIND_LABELS if k in chosen]


def _clean_page_size(page_size: int) -> int:
    return page_size if page_size in PAGE_SIZES else DEFAULT_PAGE_SIZE


def _activity_url(kinds: list[str], page_size: int, q: str = "", dc: str = "") -> str:
    """Build /activity?… so a delete/clear redirect preserves the view (filters, search, dc type)."""
    params = [("kinds", k) for k in _clean_kinds(kinds)]
    params.append(("page_size", _clean_page_size(page_size)))
    if (q or "").strip():
        params.append(("q", q.strip()))
    if dc in PROVIDER_PATHS:
        params.append(("dc", dc))
    return "/activity?" + urlencode(params)


@router.get("/activity", response_class=HTMLResponse)
def activity_page(request: Request, kinds: list[str] = Query(default=[]),
                  page_size: int = Query(DEFAULT_PAGE_SIZE), q: str = Query(""),
                  dc: str = Query(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    counts = {"all": 0}
    for k, n in db.execute(select(ActivityLog.kind, func.count()).group_by(ActivityLog.kind)).all():
        counts[k] = n
        counts["all"] += n
    dc_counts = {prov: db.scalar(select(func.count()).select_from(ActivityLog).where(
        or_(*[ActivityLog.path.like(f"%{p}%") for p in paths]))) or 0
        for prov, paths in PROVIDER_PATHS.items()}
    return templates.TemplateResponse(request, "activity.html", {
        "counts": counts, "kind_labels": KIND_LABELS, "selected": _clean_kinds(kinds),
        "page_size": _clean_page_size(page_size), "page_sizes": PAGE_SIZES,
        "provider_labels": PROVIDER_LABELS, "dc_counts": dc_counts,
        "q": q, "dc": dc if dc in PROVIDER_PATHS else "",
        "flash": _pop_flash(request),
    })


@router.get("/activity/rows", response_class=HTMLResponse)
def activity_rows(request: Request, kinds: list[str] = Query(default=[]), page: int = 1,
                  page_size: int = DEFAULT_PAGE_SIZE, q: str = "", dc: str = "",
                  db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return HTMLResponse("", status_code=401)
    sel = _clean_kinds(kinds)
    ps = _clean_page_size(page_size)
    conds = _filter_conds(sel, dc, q)
    base = select(ActivityLog)
    count_q = select(func.count()).select_from(ActivityLog)
    if conds:
        base = base.where(and_(*conds))
        count_q = count_q.where(and_(*conds))
    total = db.scalar(count_q) or 0
    pages = max(1, (total + ps - 1) // ps)
    page = min(max(1, page), pages)
    rows = db.scalars(
        base.order_by(ActivityLog.at.desc()).limit(ps).offset((page - 1) * ps)
    ).all()
    return templates.TemplateResponse(request, "_activity_rows.html", {
        "rows": rows, "kind_labels": KIND_LABELS,
        "page": page, "pages": pages, "total": total,
    })


@router.get("/activity/{log_id}", response_class=HTMLResponse)
def activity_detail(log_id: int, request: Request, db: Session = Depends(get_db)):
    """One record's full request/response — rendered into the viewer modal."""
    if get_user_or_none(request, db) is None:
        return HTMLResponse("", status_code=401)
    row = db.get(ActivityLog, log_id)
    if row is None:
        return HTMLResponse("<p class='muted'>Record not found.</p>", status_code=404)
    return templates.TemplateResponse(request, "_activity_detail.html",
                                      {"r": row, "kind_labels": KIND_LABELS})


@router.post("/activity/delete")
def activity_delete(request: Request, ids: list[int] = Form(default=[]),
                    kinds: list[str] = Form(default=[]), page_size: int = Form(DEFAULT_PAGE_SIZE),
                    q: str = Form(""), dc: str = Form(""), db: Session = Depends(get_db)):
    """Delete the selected record(s) — one or many."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    n = 0
    if ids:
        n = db.execute(delete(ActivityLog).where(ActivityLog.id.in_(ids))).rowcount or 0
        db.commit()
    _flash(request, f"Deleted {n} log entr{'y' if n == 1 else 'ies'}." if n else "No records selected.",
           "success" if n else "error")
    return RedirectResponse(_activity_url(kinds, page_size, q, dc), status_code=303)


@router.post("/activity/clear")
def activity_clear(request: Request, kinds: list[str] = Form(default=[]),
                   page_size: int = Form(DEFAULT_PAGE_SIZE), q: str = Form(""), dc: str = Form(""),
                   db: Session = Depends(get_db)):
    """Clear everything matching the current view (checked kinds / data center type / search)."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    conds = _filter_conds(_clean_kinds(kinds), dc, q)
    stmt = delete(ActivityLog)
    if conds:
        stmt = stmt.where(and_(*conds))
    n = db.execute(stmt).rowcount or 0
    db.commit()
    scope = " matching the filter" if conds else ""
    _flash(request, f"Cleared {n}{scope} log entr{'y' if n == 1 else 'ies'}.")
    return RedirectResponse(_activity_url(kinds, page_size, q, dc), status_code=303)
