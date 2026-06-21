"""Portal Settings — user-tunable behaviour for how the tool talks to a Check Point management server
(session reuse + revision-based policy cache). Auth-gated; values persist via ``services.app_settings``
(DB-backed ``AppState``) so an admin controls the behaviour from the portal, never from code or env."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..security import get_user_or_none
from ..services import app_settings
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)


def _grouped():
    groups: dict[str, list] = {}
    for s in app_settings.SETTINGS:
        groups.setdefault(s.group, []).append(s)
    return groups


@router.get("/settings", response_class=HTMLResponse)
def settings_page(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "settings.html",
                                      {"groups": _grouped(), "vals": app_settings.all_values(fresh=True),
                                       "flash": _pop_flash(request)})


@router.post("/settings")
async def settings_save(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    new: dict = {}
    for s in app_settings.SETTINGS:
        if s.kind == "bool":
            new[s.key] = s.key in form          # an unchecked checkbox is simply absent from the form
        elif s.key in form:
            new[s.key] = form[s.key]            # validated + clamped in app_settings.save()
    app_settings.save(new)
    _flash(request, "Settings saved — they take effect immediately.")
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/reset")
def settings_reset(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    app_settings.save(app_settings.defaults())
    _flash(request, "Settings restored to defaults.")
    return RedirectResponse("/settings", status_code=303)
