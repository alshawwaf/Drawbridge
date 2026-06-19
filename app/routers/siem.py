"""SIEM receiver UI: shows the logs the built-in Log Exporter listener received, with a 'how to
point Check Point here' panel and a 'Send test log' button so it can be demoed without a gateway."""
import random

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import SiemLog
from ..security import get_user_or_none
from ..services import siem
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)
_PAGE = 60


def _host() -> str:
    base = get_settings().base_url
    return base.split("://", 1)[-1].split("/")[0].split(":")[0]


@router.get("/siem", response_class=HTMLResponse)
def siem_page(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    s = get_settings()
    return templates.TemplateResponse(request, "siem.html", {
        "host": _host(), "port": s.syslog_port, "enabled": bool(s.syslog_port and s.syslog_port > 0),
        "total": db.scalar(select(func.count()).select_from(SiemLog)) or 0,
        "flash": _pop_flash(request)})


@router.get("/siem/rows", response_class=HTMLResponse)
def siem_rows(request: Request, fmt: str = "", db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return HTMLResponse("", status_code=401)
    q = select(SiemLog).order_by(SiemLog.at.desc()).limit(_PAGE)
    if fmt in ("cef", "leef", "json", "syslog", "raw"):
        q = q.where(SiemLog.fmt == fmt)
    rows = db.scalars(q).all()
    counts = dict(db.execute(select(SiemLog.fmt, func.count()).group_by(SiemLog.fmt)).all())
    total = db.scalar(select(func.count()).select_from(SiemLog)) or 0
    return templates.TemplateResponse(request, "_siem_rows.html",
                                      {"rows": rows, "total": total, "counts": counts})


@router.get("/siem/{log_id}", response_class=HTMLResponse)
def siem_detail(log_id: int, request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return HTMLResponse("", status_code=401)
    log = db.get(SiemLog, log_id)
    if log is None:
        return HTMLResponse("<p class='muted'>Record not found.</p>", status_code=404)
    return templates.TemplateResponse(request, "_siem_detail.html", {"log": log})


@router.post("/siem/test")
def siem_test(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    siem.store_log(db, "203.0.113.1", "udp", random.choice(siem.SAMPLE_LINES))
    _flash(request, "Injected a sample Log Exporter line — the receiver parsed and stored it.")
    return RedirectResponse("/siem", status_code=303)


@router.post("/siem/clear")
def siem_clear(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    db.execute(delete(SiemLog))
    db.commit()
    _flash(request, "Cleared all received logs.")
    return RedirectResponse("/siem", status_code=303)
