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
PAGE_SIZES = [10, 25, 50, 100]
DEFAULT_PAGE_SIZE = 25


def _clean_page_size(page_size: int) -> int:
    return page_size if page_size in PAGE_SIZES else DEFAULT_PAGE_SIZE


def _host() -> str:
    base = get_settings().base_url
    return base.split("://", 1)[-1].split("/")[0].split(":")[0]


@router.get("/siem", response_class=HTMLResponse)
def siem_page(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    s = get_settings()
    resp = templates.TemplateResponse(request, "siem.html", {
        "host": _host(), "port": s.syslog_port, "enabled": bool(s.syslog_port and s.syslog_port > 0),
        "total": db.scalar(select(func.count()).select_from(SiemLog)) or 0,
        "page_sizes": PAGE_SIZES, "page_size": DEFAULT_PAGE_SIZE, "paused": siem.is_paused(db, fresh=True),
        "flash": _pop_flash(request)})
    resp.headers["Cache-Control"] = "no-store"   # never serve a stale Paused/Listening state
    return resp


@router.get("/siem/rows", response_class=HTMLResponse)
def siem_rows(request: Request, fmt: str = "", page: int = 1,
              page_size: int = DEFAULT_PAGE_SIZE, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return HTMLResponse("", status_code=401)
    ps = _clean_page_size(page_size)
    base = select(SiemLog)
    cnt = select(func.count()).select_from(SiemLog)
    if fmt in ("cef", "leef", "json", "keyval", "syslog", "raw"):
        base = base.where(SiemLog.fmt == fmt)
        cnt = cnt.where(SiemLog.fmt == fmt)
    matched = db.scalar(cnt) or 0
    pages = max(1, (matched + ps - 1) // ps)
    page = min(max(1, page), pages)
    rows = db.scalars(base.order_by(SiemLog.at.desc()).limit(ps).offset((page - 1) * ps)).all()
    counts = dict(db.execute(select(SiemLog.fmt, func.count()).group_by(SiemLog.fmt)).all())
    total = db.scalar(select(func.count()).select_from(SiemLog)) or 0
    return templates.TemplateResponse(request, "_siem_rows.html",
                                      {"rows": rows, "total": total, "counts": counts,
                                       "page": page, "pages": pages, "matched": matched})


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


@router.post("/siem/pause")
def siem_pause(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    siem.set_paused(db, True)
    _flash(request, "Receiving paused — incoming logs are dropped until you resume (the listener stays up).")
    return RedirectResponse("/siem", status_code=303)


@router.post("/siem/resume")
def siem_resume(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    siem.set_paused(db, False)
    _flash(request, "Receiving resumed — logs will land on the page again.")
    return RedirectResponse("/siem", status_code=303)


@router.post("/siem/clear")
def siem_clear(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    db.execute(delete(SiemLog))
    db.commit()
    _flash(request, "Cleared all received logs.")
    return RedirectResponse("/siem", status_code=303)
