"""Dynamic Layers UI: author objects + rulebase -> preview the set-dynamic-content payload ->
apply to the built-in mock or a real R82 gateway -> review the task result & history."""
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import DynamicLayer, Gateway, User
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
from ..services.apply_runner import STAGES, fetch_dynamic_content, get_progress, start_apply
from ..services.gaia_client import fetch_gateway_cert
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
    gws = {g.id: g for g in db.scalars(select(Gateway).where(Gateway.owner_id == user.id)).all()}
    rows = []
    gw_counts: dict[str, int] = {}
    for layer in layers:
        objs = sum(len(v or []) for v in (layer.content.get("objects") or {}).values())
        gid = (layer.content or {}).get("gateway_id")
        gw = gws.get(gid)
        key = str(gid) if gw else "none"
        gw_counts[key] = gw_counts.get(key, 0) + 1
        rows.append({
            "layer": layer, "objects": objs,
            "rules": len(layer.content.get("rulebase") or []),
            "last": layer.tasks[0] if layer.tasks else None,
            "gateway": gw.name if gw else None, "gw_key": key,
        })
    gw_filters = [{"key": str(g.id), "name": g.name, "count": gw_counts.get(str(g.id), 0)} for g in gws.values()]
    if gw_counts.get("none"):
        gw_filters.append({"key": "none", "name": "No gateway", "count": gw_counts["none"]})
    return templates.TemplateResponse(request, "dynamic_list.html",
        {"rows": rows, "gw_filters": gw_filters, "flash": _pop_flash(request)})


@router.get("/layers/new", response_class=HTMLResponse)
def layers_new(request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    gateways = db.scalars(select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.name)).all()
    ctx = dict(_BUILDER_CTX)
    ctx.update({
        "error": None, "default_content": DEFAULT_LAYER_CONTENT,
        "gateways": gateways, "selected_gateway_id": "",
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
    gateway_id: str = Form(""),
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
        if gateway_id:
            try:
                content["gateway_id"] = int(gateway_id)
            except ValueError:
                pass
        validate_layer_content(content)
    except Exception as exc:
        gateways = db.scalars(select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.name)).all()
        ctx = dict(_BUILDER_CTX)
        ctx.update({
            "error": str(exc), "gateways": gateways, "selected_gateway_id": gateway_id,
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
        "trace": result.get("trace", []) or [],
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
    gws = db.scalars(select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.name)).all()
    gateways = [{"id": g.id, "name": g.name, "host": g.host, "port": g.port,
                 "username": g.username, "cert_pem": g.cert_pem} for g in gws]
    return templates.TemplateResponse(request, "dynamic_detail.html", {
        "layer": layer, "payload_json": payload_json, "tasks": tasks,
        "latest": tasks[0] if tasks else None,
        "gateways": gateways, "layer_gateway_id": (layer.content or {}).get("gateway_id"),
        "mock_url": f"{base}/gaia_api/v1.9", "flash": _pop_flash(request),
    })


@router.post("/layers/{layer_id}/apply-start")
def apply_start(
    layer_id: int,
    request: Request,
    use_mock: str = Form(""),
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
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    layer = _owned(db, layer_id, user)
    dry = bool(dry_run)
    if use_mock:
        pid = start_apply(layer_id=layer.id, target="mock", dry_run=dry)
    else:
        if not (gw_host and gw_user and gw_pass):
            return JSONResponse({"error": "Gateway address, username, and password are required "
                                          "(or tick “Use mock gateway”)."}, status_code=400)
        try:
            port = int(gw_port or 443)
        except ValueError:
            port = 443
        pid = start_apply(layer_id=layer.id, target="gateway", dry_run=dry, gateway_host=gw_host,
                          gateway_port=port, user=gw_user, password=gw_pass, cert_pem=gw_cert or None)
    return JSONResponse({"progress_id": pid})


@router.get("/layers/{layer_id}/apply-status/{pid}")
def apply_status(layer_id: int, pid: str, request: Request, db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    p = get_progress(pid)
    if p is None:
        return JSONResponse({"error": "unknown progress id"}, status_code=404)
    return JSONResponse({
        "stage": p["stage"], "status": p["status"], "done_stages": p["done_stages"],
        "failed_stage": p.get("failed_stage"),
        "summary": p.get("summary"), "error": p.get("error"), "task_id": p.get("task_id"),
        "trace": p.get("trace", []),
        "stages": [{"key": k, "label": label} for k, label in STAGES],
    })


@router.post("/layers/{layer_id}/fetch-content")
def fetch_content(
    layer_id: int, request: Request,
    use_mock: str = Form(""), gw_host: str = Form(""), gw_port: str = Form("443"),
    gw_user: str = Form(""), gw_pass: str = Form(""), gw_cert: str = Form(""),
    db: Session = Depends(get_db),
):
    """Read the dynamic layers / content a gateway (real or mock) currently has."""
    user = _user(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    _owned(db, layer_id, user)
    if use_mock:
        data = fetch_dynamic_content(target="mock", db=db, owner_id=user.id)
    else:
        if not (gw_host and gw_user and gw_pass):
            return JSONResponse({"error": "Gateway address, username, and password are required "
                                          "(or tick “Use mock gateway”)."}, status_code=400)
        try:
            port = int(gw_port or 443)
        except ValueError:
            port = 443
        data = fetch_dynamic_content(target="gateway", db=db, owner_id=user.id, host=gw_host,
                                     port=port, user=gw_user, password=gw_pass, cert_pem=gw_cert or None)
    return JSONResponse(data)


@router.post("/layers/{layer_id}/fetch-cert")
def fetch_cert(layer_id: int, request: Request, gw_host: str = Form(""),
               gw_port: str = Form("443"), db: Session = Depends(get_db)):
    user = _user(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    _owned(db, layer_id, user)
    if not gw_host:
        return JSONResponse({"error": "Enter the gateway address first."}, status_code=400)
    try:
        port = int(gw_port or 443)
    except ValueError:
        port = 443
    try:
        return JSONResponse(fetch_gateway_cert(gw_host, port))
    except Exception as exc:
        return JSONResponse({"error": f"Could not fetch certificate from {gw_host}:{port} — {exc}"}, status_code=400)


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
