"""App-wide Activity log: live, filterable view of integration traffic with request/response."""
from fastapi import APIRouter, Depends, Request
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

PAGE_SIZE = 50  # events per page in the full Activity log view


@router.get("/activity", response_class=HTMLResponse)
def activity_page(request: Request, kind: str = "all", db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    counts = {"all": 0}
    for k, n in db.execute(select(ActivityLog.kind, func.count()).group_by(ActivityLog.kind)).all():
        counts[k] = n
        counts["all"] += n
    return templates.TemplateResponse(request, "activity.html", {
        "kind": kind, "counts": counts, "kind_labels": KIND_LABELS, "flash": _pop_flash(request),
    })


@router.get("/activity/rows", response_class=HTMLResponse)
def activity_rows(request: Request, kind: str = "all", page: int = 1, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return HTMLResponse("", status_code=401)
    base = select(ActivityLog)
    count_q = select(func.count()).select_from(ActivityLog)
    if kind != "all":
        base = base.where(ActivityLog.kind == kind)
        count_q = count_q.where(ActivityLog.kind == kind)
    total = db.scalar(count_q) or 0
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    page = min(max(1, page), pages)
    rows = db.scalars(
        base.order_by(ActivityLog.at.desc()).limit(PAGE_SIZE).offset((page - 1) * PAGE_SIZE)
    ).all()
    return templates.TemplateResponse(request, "_activity_rows.html", {
        "rows": rows, "kind_labels": KIND_LABELS,
        "kind": kind, "page": page, "pages": pages, "total": total,
    })


@router.post("/activity/clear")
def activity_clear(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    db.execute(delete(ActivityLog))
    db.commit()
    _flash(request, "Activity log cleared.")
    return RedirectResponse("/activity", status_code=303)
