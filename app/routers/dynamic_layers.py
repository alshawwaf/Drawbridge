"""Dynamic Layers UI: author objects + rulebase -> preview the set-dynamic-content payload ->
apply to the built-in mock or a real R82 gateway -> review the task result & history."""
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import DynamicLayer, User
from ..schemas.dynamic_layer import (
    OBJECT_SPECS,
    OBJECT_TYPES,
    REFERENCE_TYPES,
    RULE_ACTIONS,
    TRACK_TYPES,
    build_set_dynamic_content,
    validate_layer_content,
)
from ..security import get_user_or_none, new_feed_token
from ..services.gaia_client import apply_to_gateway
from ..services.layer_apply import apply_to_mock
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)

# Pre-filled sample so the builder opens with a working example (the docs' "Simple Objects" shape).
DEFAULT_LAYER_CONTENT = {
    "operation": "replace",
    "objects": {
        "hosts": [{"name": "client", "ip-address": "10.0.0.5"}],
        "networks": [{"name": "lab_net", "subnet4": "10.0.0.0", "mask-length4": 24}],
    },
    "rulebase": [
        {"name": "allow_client", "action": "Accept", "track": {"type": "Log"},
         "source": ["client"], "destination": ["lab_net"], "service": "any"},
        {"name": "cleanup_rule", "action": "Drop", "track": {"type": "Log"},
         "source": "any", "destination": "any", "service": "any"},
    ],
    "referenced_objects": {},
}

_BUILDER_CTX = {
    "specs": OBJECT_SPECS, "object_types": OBJECT_TYPES, "ref_types": REFERENCE_TYPES,
    "actions": RULE_ACTIONS, "tracks": TRACK_TYPES,
}


def _user(request: Request, db: Session) -> User | None:
    return get_user_or_none(request, db)


def _owned(db: Session, layer_id: int, user: User) -> DynamicLayer:
    layer = db.get(DynamicLayer, layer_id)
    if layer is None or layer.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Dynamic Layer not found")
    return layer


@router.get("/layers", response_class=HTMLResponse)
def layers_list(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layers = db.scalars(
        select(DynamicLayer).where(DynamicLayer.owner_id == user.id).order_by(DynamicLayer.created_at.desc())
    ).all()
    rows = []
    for layer in layers:
        objs = sum(len(v or []) for v in (layer.content.get("objects") or {}).values())
        rows.append({
            "layer": layer, "objects": objs,
            "rules": len(layer.content.get("rulebase") or []),
            "last": layer.tasks[0] if layer.tasks else None,
        })
    return templates.TemplateResponse(request, "dynamic_list.html", {"rows": rows, "flash": _pop_flash(request)})


@router.get("/layers/new", response_class=HTMLResponse)
def layers_new(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    ctx = dict(_BUILDER_CTX)
    ctx.update({
        "error": None, "default_content": DEFAULT_LAYER_CONTENT,
        "form": {"name": "Self-managed-demo", "layer_name": "dynamic_layer",
                 "description": "", "comments": "", "tags": ""},
    })
    return templates.TemplateResponse(request, "dynamic_new.html", ctx)


@router.post("/layers/new")
def layers_create(
    request: Request,
    name: str = Form(...),
    layer_name: str = Form("dynamic_layer"),
    description: str = Form(""),
    comments: str = Form(""),
    tags: str = Form(""),
    objects_json: str = Form("{}"),
    rules_json: str = Form("[]"),
    referenced_json: str = Form("{}"),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        objects = json.loads(objects_json or "{}")
        rulebase = json.loads(rules_json or "[]")
        referenced = json.loads(referenced_json or "{}")
        content = {
            "operation": "replace", "comments": comments,
            "tags": [t.strip() for t in tags.split(",") if t.strip()],
            "objects": objects, "rulebase": rulebase, "referenced_objects": referenced,
        }
        validate_layer_content(content)
    except Exception as exc:
        ctx = dict(_BUILDER_CTX)
        ctx.update({
            "error": str(exc),
            "default_content": {"objects": _safe_json(objects_json, {}),
                                "rulebase": _safe_json(rules_json, []),
                                "referenced_objects": _safe_json(referenced_json, {})},
            "form": {"name": name, "layer_name": layer_name, "description": description,
                     "comments": comments, "tags": tags},
        })
        return templates.TemplateResponse(request, "dynamic_new.html", ctx, status_code=400)
    layer = DynamicLayer(token=new_feed_token(), name=name, layer_name=layer_name or "dynamic_layer",
                         description=description, content=content, owner_id=user.id)
    db.add(layer)
    db.commit()
    db.refresh(layer)
    _flash(request, f"Dynamic Layer “{name}” saved.")
    return RedirectResponse(f"/layers/{layer.id}", status_code=303)


def _safe_json(text: str, default):
    try:
        return json.loads(text or "")
    except Exception:
        return default


def _task_view(task) -> dict:
    result = task.result or {}
    cs = result.get("change_summary", {}) or {}
    layers = cs.get("layers", []) or []
    rules_created = sum(len((lyr.get("rules", {}) or {}).get("create", []) or []) for lyr in layers)
    objects_created = (cs.get("objects", {}) or {}).get("create", []) or []
    return {
        "t": task,
        "layers": layers,
        "rules_created": rules_created,
        "objects_created": objects_created,
        "warnings": result.get("validation_warnings", []) or [],
        "errors": result.get("validation_errors", []) or [],
    }


@router.get("/layers/{layer_id}", response_class=HTMLResponse)
def layer_detail(layer_id: int, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    payload_json = json.dumps(build_set_dynamic_content(layer), indent=2)
    base = get_settings().base_url.rstrip("/")
    tasks = [_task_view(t) for t in layer.tasks[:25]]
    return templates.TemplateResponse(request, "dynamic_detail.html", {
        "layer": layer, "payload_json": payload_json, "tasks": tasks,
        "latest": tasks[0] if tasks else None,
        "mock_url": f"{base}/gaia_api/v1.9", "flash": _pop_flash(request),
    })


@router.post("/layers/{layer_id}/apply")
def layer_apply(
    layer_id: int,
    request: Request,
    target: str = Form("mock"),
    dry_run: str = Form(""),
    gw_host: str = Form(""),
    gw_port: str = Form("443"),
    gw_user: str = Form(""),
    gw_pass: str = Form(""),
    gw_cert: str = Form(""),
    db: Session = Depends(get_db),
):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    dry = bool(dry_run)
    if target == "gateway":
        if not (gw_host and gw_user and gw_pass):
            _flash(request, "Gateway address, username, and password are required.", "error")
            return RedirectResponse(f"/layers/{layer_id}", status_code=303)
        try:
            port = int(gw_port or 443)
        except ValueError:
            port = 443
        task = apply_to_gateway(db, layer, host=gw_host, port=port, user=gw_user,
                                password=gw_pass, dry_run=dry, cert_pem=gw_cert or None)
    else:
        task = apply_to_mock(db, layer, dry_run=dry)
    verb = "Dry-run" if dry else "Apply"
    _flash(request, f"{verb} to {task.target}: {task.status}.",
           "success" if task.status == "succeeded" else "error")
    return RedirectResponse(f"/layers/{layer_id}", status_code=303)


@router.post("/layers/{layer_id}/delete")
def layer_delete(layer_id: int, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    layer = _owned(db, layer_id, user)
    name = layer.name
    db.delete(layer)
    db.commit()
    _flash(request, f"Dynamic Layer “{name}” deleted.")
    return RedirectResponse("/layers", status_code=303)


@router.get("/layers/{layer_id}/payload")
def layer_payload(layer_id: int, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return Response("", status_code=401)
    layer = _owned(db, layer_id, user)
    return Response(json.dumps(build_set_dynamic_content(layer), indent=2), media_type="application/json")
