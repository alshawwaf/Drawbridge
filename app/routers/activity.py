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
               "api": "API", "ui": "Page view"}


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
def activity_rows(request: Request, kind: str = "all", db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return HTMLResponse("", status_code=401)
    stmt = select(ActivityLog).order_by(ActivityLog.at.desc()).limit(100)
    if kind != "all":
        stmt = select(ActivityLog).where(ActivityLog.kind == kind).order_by(ActivityLog.at.desc()).limit(100)
    rows = db.scalars(stmt).all()
    return templates.TemplateResponse(request, "_activity_rows.html", {"rows": rows, "kind_labels": KIND_LABELS})


@router.post("/activity/clear")
def activity_clear(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    db.execute(delete(ActivityLog))
    db.commit()
    _flash(request, "Activity log cleared.")
    return RedirectResponse("/activity", status_code=303)
