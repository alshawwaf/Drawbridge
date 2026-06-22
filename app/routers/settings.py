"""Portal Settings — user-tunable behaviour for how the tool talks to a Check Point management server
(session reuse + revision-based policy cache). Auth-gated; values persist via ``services.app_settings``
(DB-backed ``AppState``) so an admin controls the behaviour from the portal, never from code or env."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..security import get_user_or_none
from ..services import api_keys, app_settings, table_prefs
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
    new_key = request.session.pop("new_api_key", None)   # one-time reveal (NOT via _flash → not persisted)
    return templates.TemplateResponse(request, "settings.html",
                                      {"groups": _grouped(), "vals": app_settings.all_values(fresh=True),
                                       "secrets": app_settings.secret_status(),       # {key: is_set} — never the value
                                       "crypto_ok": app_settings.secret_available(),
                                       "api_keys": api_keys.list_keys(),
                                       "api_scopes": api_keys.SCOPES,
                                       "new_key": new_key,
                                       "flash": _pop_flash(request)})


@router.post("/settings")
async def settings_save(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    new: dict = {}
    for s in app_settings.SETTINGS:
        if s.kind == "secret":
            continue                            # secrets handled write-only below, never echoed/round-tripped
        if s.kind == "bool":
            new[s.key] = s.key in form          # an unchecked checkbox is simply absent from the form
        elif s.key in form:
            new[s.key] = form[s.key]            # validated + clamped in app_settings.save()
    app_settings.save(new)

    # Secrets are write-only: a blank field means "keep current"; a "<key>__clear" checkbox removes it;
    # a non-empty value sets/rotates it (encrypted at rest). Refuse cleartext storage if crypto is off.
    secret_err = None
    for s in app_settings.secret_settings():
        if form.get(s.key + "__clear"):
            app_settings.clear_secret(s.key)
            continue
        value = (form.get(s.key) or "").strip()
        if value:
            try:
                app_settings.set_secret(s.key, value)
            except RuntimeError:
                secret_err = ("Can't store secrets: at-rest encryption is unavailable. Set "
                              "DCSIM_ENCRYPTION_KEY (or DCSIM_SESSION_SECRET) and restart, or keep using "
                              "the DCSIM_* env vars.")
    _flash(request, secret_err or "Settings saved — they take effect immediately.")
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/reset")
def settings_reset(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    app_settings.save(app_settings.defaults())
    _flash(request, "Settings restored to defaults.")
    return RedirectResponse("/settings", status_code=303)


@router.post("/settings/api-keys")
async def api_key_create(request: Request, db: Session = Depends(get_db)):
    """Generate a new API key. The plaintext is shown ONCE via a one-time session entry (never written
    to the notification log), then only its hash remains."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    name = (form.get("name") or "").strip() or "key"
    scope = form.get("scope") or "mcp"
    row, secret = api_keys.generate(name, scope, created_by=user.username)
    request.session["new_api_key"] = {"name": row.name, "scope": row.scope, "key": secret}
    _flash(request, f"API key '{row.name}' ({row.scope}) created — copy it now, it's shown only once.")
    return RedirectResponse("/settings#grp-api-keys", status_code=303)


@router.post("/settings/api-keys/{key_id}/revoke")
def api_key_revoke(key_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if api_keys.revoke(key_id):
        _flash(request, "API key revoked — it can no longer authenticate.")
    return RedirectResponse("/settings#grp-api-keys", status_code=303)


@router.post("/prefs/table/{table_id}/columns")
async def save_table_columns(table_id: str, request: Request, db: Session = Depends(get_db)):
    """Persist a user's visible-column choice for a table, then return to the page (server re-renders
    the chosen columns — no flash). Column ids are validated against the table's spec allowlist."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    form = await request.form()
    nxt = str(form.get("next") or "")
    if not nxt.startswith("/"):
        nxt = "/"
    if table_prefs.spec(table_id):                      # ignore unknown table ids (no junk rows)
        if "reset" in form:
            table_prefs.reset(db, user.id, table_id)
        else:
            table_prefs.save_columns(db, user.id, table_id, form.getlist("cols"))
    return RedirectResponse(nxt, status_code=303)
