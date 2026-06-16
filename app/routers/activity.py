"""App-wide Activity log: live, filterable view of integration traffic with request/response."""
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import ActivityLog
from ..security import get_user_or_none
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)

KIND_LABELS = {"feed_poll": "Feed poll", "gaia_mock": "Mock Gaia API", "layer_apply": "Layer apply",
               "gateway_read": "Gateway read", "datacenter": "Data Center", "api": "API", "ui": "Page view"}

PAGE_SIZES = [10, 25, 50, 100]
DEFAULT_PAGE_SIZE = 10


def _clean_kinds(kinds: list[str]) -> list[str]:
    """Keep only valid kinds, in the canonical KIND_LABELS order (deduped)."""
    chosen = set(kinds or [])
    return [k for k in KIND_LABELS if k in chosen]


def _clean_page_size(page_size: int) -> int:
    return page_size if page_size in PAGE_SIZES else DEFAULT_PAGE_SIZE


def _activity_url(kinds: list[str], page_size: int) -> str:
    """Build /activity?kinds=…&page_size=… so a delete/clear redirect preserves the view."""
    params = [("kinds", k) for k in _clean_kinds(kinds)]
    params.append(("page_size", _clean_page_size(page_size)))
    return "/activity?" + urlencode(params)


@router.get("/activity", response_class=HTMLResponse)
def activity_page(request: Request, kinds: list[str] = Query(default=[]),
                  page_size: int = Query(DEFAULT_PAGE_SIZE), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    counts = {"all": 0}
    for k, n in db.execute(select(ActivityLog.kind, func.count()).group_by(ActivityLog.kind)).all():
        counts[k] = n
        counts["all"] += n
    return templates.TemplateResponse(request, "activity.html", {
        "counts": counts, "kind_labels": KIND_LABELS, "selected": _clean_kinds(kinds),
        "page_size": _clean_page_size(page_size), "page_sizes": PAGE_SIZES,
        "flash": _pop_flash(request),
    })


@router.get("/activity/rows", response_class=HTMLResponse)
def activity_rows(request: Request, kinds: list[str] = Query(default=[]), page: int = 1,
                  page_size: int = DEFAULT_PAGE_SIZE, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return HTMLResponse("", status_code=401)
    sel = _clean_kinds(kinds)
    ps = _clean_page_size(page_size)
    base = select(ActivityLog)
    count_q = select(func.count()).select_from(ActivityLog)
    if sel:  # no kind checked = show everything
        base = base.where(ActivityLog.kind.in_(sel))
        count_q = count_q.where(ActivityLog.kind.in_(sel))
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
                    db: Session = Depends(get_db)):
    """Delete the selected record(s) — one or many."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    n = 0
    if ids:
        n = db.execute(delete(ActivityLog).where(ActivityLog.id.in_(ids))).rowcount or 0
        db.commit()
    _flash(request, f"Deleted {n} log entr{'y' if n == 1 else 'ies'}." if n else "No records selected.",
           "success" if n else "error")
    return RedirectResponse(_activity_url(kinds, page_size), status_code=303)


@router.post("/activity/clear")
def activity_clear(request: Request, kinds: list[str] = Form(default=[]),
                   page_size: int = Form(DEFAULT_PAGE_SIZE), db: Session = Depends(get_db)):
    """Clear everything, or just the checked categories (leaving the others intact)."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    sel = _clean_kinds(kinds)
    q = delete(ActivityLog)
    if sel:
        q = q.where(ActivityLog.kind.in_(sel))
    n = db.execute(q).rowcount or 0
    db.commit()
    scope = "" if not sel else " " + ", ".join(KIND_LABELS.get(k, k) for k in sel)
    _flash(request, f"Cleared {n}{scope} log entr{'y' if n == 1 else 'ies'}.")
    return RedirectResponse(_activity_url(kinds, page_size), status_code=303)
