"""Live-mutation control panel — the demo 'scenario engine'.

Mutate a Data Center's simulated inventory on cue (flip a tag, add/remove a workload) and the
gateway's next ~30s scan re-resolves the affected objects/rules — no push needed, because CloudGuard
polls. The baseline is captured automatically before the first mutation so 'Reset to baseline'
restores the pre-demo state. Backed by ``app/services/scenarios.py``.
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Datacenter, DatacenterBaseline
from ..security import get_user_or_none
from ..services import scenario_runner, scenarios
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)

_SYNC = "CloudGuard re-syncs within ~30s."


def _owned(db: Session, dc_id: int, user) -> Datacenter:
    dc = db.get(Datacenter, dc_id)
    if dc is None or dc.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Datacenter not found")
    return dc


def _capture_baseline(db: Session, dc: Datacenter) -> None:
    """Snapshot the current inventory as the reset target — once, before the first mutation."""
    if dc.baseline is None:
        db.add(DatacenterBaseline(datacenter_id=dc.id, content=scenarios.snapshot(dc.content)))


@router.get("/scenarios", response_class=HTMLResponse)
def scenarios_page(request: Request, dc: int = 0, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dcs = db.scalars(
        select(Datacenter).where(Datacenter.owner_id == user.id).order_by(Datacenter.created_at.desc())
    ).all()
    rows = [{"dc": d, "count": len(scenarios.workloads(d.provider, d.content)),
             "taggable": scenarios.supports_tags(d.provider)} for d in dcs]
    selected = next((d for d in dcs if d.id == dc), None)
    ctx = {"rows": rows, "selected": selected, "flash": _pop_flash(request)}
    if selected:
        ctx.update({
            "workloads": scenarios.workloads(selected.provider, selected.content),
            "taggable": scenarios.supports_tags(selected.provider),
            "map_tags": scenarios.is_map_tags(selected.provider),
            "tag_field": scenarios.tag_field(selected.provider),
            "has_baseline": selected.baseline is not None,
            "presets": scenarios.list_presets(selected.provider, selected.content),
        })
    return templates.TemplateResponse(request, "scenarios.html", ctx)


@router.post("/scenarios/{dc_id}/mutate")
def mutate(dc_id: int, request: Request, action: str = Form(...), name: str = Form(""),
           value: str = Form(""), ip: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    try:
        _capture_baseline(db, dc)
        new, desc = scenarios.apply_action(dc.provider, dc.content, action, name=name, value=value, ip=ip)
        dc.content = new
        db.commit()
        _flash(request, f"{desc} — {_SYNC}")
    except Exception as exc:
        db.rollback()
        _flash(request, str(exc), "error")
    return RedirectResponse(f"/scenarios?dc={dc_id}", status_code=303)


@router.post("/scenarios/{dc_id}/set-baseline")
def set_baseline(dc_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    if dc.baseline is None:
        db.add(DatacenterBaseline(datacenter_id=dc.id, content=scenarios.snapshot(dc.content)))
    else:
        dc.baseline.content = scenarios.snapshot(dc.content)
    db.commit()
    _flash(request, "Baseline set to the current inventory.")
    return RedirectResponse(f"/scenarios?dc={dc_id}", status_code=303)


@router.post("/scenarios/{dc_id}/reset")
def reset(dc_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    if dc.baseline is None:
        _flash(request, "No baseline captured yet — mutate something or click ‘Set baseline’ first.", "error")
    else:
        dc.content = scenarios.restore(dc.baseline.content)
        db.commit()
        _flash(request, f"Reset to baseline — {_SYNC}")
    return RedirectResponse(f"/scenarios?dc={dc_id}", status_code=303)


@router.post("/scenarios/{dc_id}/run")
async def run_scenario(dc_id: int, request: Request, preset: str = Form(...),
                       interval: int = Form(0), db: Session = Depends(get_db)):
    """Expand a named preset against the live inventory and start the server-side timed runner."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    try:
        _capture_baseline(db, dc)
        db.commit()                                # persist the reset target before the runner mutates
        label, steps = scenarios.plan_preset(preset, dc.provider, dc.content)
    except Exception as exc:
        db.rollback()
        _flash(request, str(exc), "error")
        return RedirectResponse(f"/scenarios?dc={dc_id}", status_code=303)
    interval = max(0, min(interval, 600))
    scenario_runner.start_run(dc.id, dc.name, label, steps, interval)
    pace = f"every {interval}s" if interval else "all at once"
    _flash(request, f"Running “{label}” — {len(steps)} step{'s' if len(steps) != 1 else ''}, {pace}. {_SYNC}")
    return RedirectResponse(f"/scenarios?dc={dc_id}", status_code=303)


@router.post("/scenarios/{dc_id}/stop")
def stop_scenario(dc_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    _owned(db, dc_id, user)
    _flash(request, "Scenario stopped." if scenario_runner.stop_run(dc_id) else "No scenario was running.")
    return RedirectResponse(f"/scenarios?dc={dc_id}", status_code=303)


@router.get("/scenarios/{dc_id}/run-status", response_class=HTMLResponse)
def run_status(dc_id: int, request: Request, db: Session = Depends(get_db)):
    """Timeline fragment for the DC's latest run (polled by the page); empty when there's none."""
    user = get_user_or_none(request, db)
    if user is None:
        return HTMLResponse("", status_code=401)
    _owned(db, dc_id, user)
    run = scenario_runner.get_run(dc_id)
    if not run:
        return HTMLResponse("")
    return templates.TemplateResponse(request, "scenario_timeline.html", {"run": run})
