"""Background apply runner with live progress.

Runs the Gaia API session (login -> set-dynamic-content -> poll show-task -> logout) in a
daemon thread and reports the current stage via an in-memory progress map that the UI polls,
so the end user sees the session unfold. Works for the built-in mock (in-process, stepped for
visibility) and for a real gateway (real httpx calls). TLS verification is never disabled —
a real gateway uses the system trust store or a pinned certificate.
"""
import os
import tempfile
import threading
import time
import uuid

import httpx

from ..db import SessionLocal
from ..models import DynamicLayer, LayerTask
from ..schemas.dynamic_layer import build_set_dynamic_content, evaluate_dynamic_content

GAIA_VERSION = "v1.9"

# Ordered session stages shown in the progress modal (key, human label).
STAGES = [
    ("connecting", "Connecting"),
    ("logging_in", "Logging in"),
    ("pushing", "Pushing policy"),
    ("polling", "Waiting for task"),
    ("logging_out", "Logging out"),
    ("done", "Done"),
]

_PROGRESS: dict[str, dict] = {}


def get_progress(pid: str) -> dict | None:
    return _PROGRESS.get(pid)


def _summary(result: dict) -> dict:
    cs = result.get("change_summary", {}) or {}
    return {
        "rules": sum(len((lyr.get("rules", {}) or {}).get("create", [])) for lyr in cs.get("layers", [])),
        "objects": len((cs.get("objects", {}) or {}).get("create", [])),
        "warnings": len(result.get("validation_warnings", [])),
        "errors": len(result.get("validation_errors", [])),
    }


def _advance(pid: str, stage: str) -> None:
    p = _PROGRESS[pid]
    if p["stage"] not in ("queued", stage) and p["stage"] not in p["done_stages"]:
        p["done_stages"].append(p["stage"])
    p["stage"] = stage


def _finish(pid: str, *, status: str, result: dict, task_id: str) -> None:
    p = _PROGRESS[pid]
    for key, _ in STAGES:
        if key != "done" and key not in p["done_stages"]:
            p["done_stages"].append(key)
    p.update(stage="done", status=status, task_id=task_id, summary=_summary(result))
    if result.get("validation_errors"):
        p["error"] = result["validation_errors"][0].get("message", "")


def start_apply(*, layer_id: int, target: str, dry_run: bool, gateway_host: str | None = None,
                gateway_port: int = 443, user: str | None = None, password: str | None = None,
                cert_pem: str | None = None) -> str:
    pid = uuid.uuid4().hex
    _PROGRESS[pid] = {"stage": "queued", "status": "running", "target": target,
                      "done_stages": [], "task_id": None, "summary": None, "error": None}
    threading.Thread(
        target=_run, args=(pid,),
        kwargs=dict(layer_id=layer_id, target=target, dry_run=dry_run, gateway_host=gateway_host,
                    gateway_port=gateway_port, user=user, password=password, cert_pem=cert_pem),
        daemon=True,
    ).start()
    return pid


def _run(pid, *, layer_id, target, dry_run, gateway_host, gateway_port, user, password, cert_pem):
    db = SessionLocal()
    cert_file = None
    result = {"change_summary": {}, "validation_warnings": [], "validation_errors": [], "dry_run": dry_run}
    status, status_code, task_id = "failed", 0, ""
    try:
        layer = db.get(DynamicLayer, layer_id)
        if layer is None:
            _PROGRESS[pid].update(stage="done", status="failed", error="Layer not found.")
            return
        payload = build_set_dynamic_content(layer, dry_run=dry_run)

        if target == "mock":
            # In-process mock — step through the same session stages so the flow is visible.
            _advance(pid, "connecting"); time.sleep(0.3)
            _advance(pid, "logging_in"); time.sleep(0.3)
            _advance(pid, "pushing"); time.sleep(0.35)
            result = evaluate_dynamic_content(payload)
            _advance(pid, "polling"); time.sleep(0.3)
            _advance(pid, "logging_out"); time.sleep(0.25)
            status, status_code, task_id = result["status"], result["status_code"], uuid.uuid4().hex
        else:
            verify: bool | str = True
            if cert_pem and cert_pem.strip():
                cert_file = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
                cert_file.write(cert_pem)
                cert_file.close()
                verify = cert_file.name
            base = f"https://{gateway_host}:{gateway_port}/gaia_api/{GAIA_VERSION}"
            try:
                with httpx.Client(verify=verify, timeout=30.0) as client:
                    _advance(pid, "connecting")
                    login = client.post(f"{base}/login", json={"user": user, "password": password})
                    login.raise_for_status()
                    sid = login.json().get("sid")
                    _advance(pid, "logging_in")
                    headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
                    try:
                        _advance(pid, "pushing")
                        resp = client.post(f"{base}/set-dynamic-content", json=payload, headers=headers)
                        status_code = resp.status_code
                        task_id = (resp.json() or {}).get("task-id", "")
                        _advance(pid, "polling")
                        details = {}
                        if task_id:
                            for _ in range(20):
                                tr = client.post(f"{base}/show-task", json={"task-id": task_id}, headers=headers)
                                tasks = (tr.json() or {}).get("tasks", [])
                                if tasks and tasks[0].get("status") in ("succeeded", "failed"):
                                    t = tasks[0]
                                    details = (t.get("task-details") or [{}])[0]
                                    status = t.get("status", "failed")
                                    status_code = t.get("status-code", status_code)
                                    break
                                time.sleep(0.4)
                        result = {
                            "change_summary": details.get("change-summary", {}),
                            "validation_warnings": details.get("validation-warnings", []),
                            "validation_errors": details.get("validation-errors", []),
                            "dry_run": dry_run,
                        }
                    finally:
                        _advance(pid, "logging_out")
                        try:
                            client.post(f"{base}/logout", headers=headers)
                        except Exception:
                            pass
            except httpx.ConnectError as exc:
                result["validation_errors"] = [{"layer": "", "rule": "", "object": "",
                    "message": "Could not reach the gateway, or TLS verification failed — use "
                               f"'Fetch & trust certificate' to pin a self-signed gateway: {exc}"}]
            except Exception as exc:
                result["validation_errors"] = [{"layer": "", "rule": "", "object": "",
                    "message": f"Gateway request failed: {exc}"}]

        task = LayerTask(task_id=task_id or uuid.uuid4().hex, layer_id=layer_id, target=target,
                         gateway_host=gateway_host, dry_run=dry_run, status=status,
                         status_code=status_code, result=result)
        db.add(task)
        db.commit()
        db.refresh(task)
        _finish(pid, status=status, result=result, task_id=task.task_id)
    except Exception as exc:
        _PROGRESS[pid].update(stage="done", status="failed", error=str(exc))
    finally:
        db.close()
        if cert_file:
            try:
                os.unlink(cert_file.name)
            except OSError:
                pass
