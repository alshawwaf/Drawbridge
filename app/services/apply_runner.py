"""Background apply runner with live progress AND a full request/response trace.

Runs the Gaia API session (login -> set-dynamic-content -> poll show-task -> logout) in a
daemon thread, reporting the current stage via an in-memory progress map the UI polls. Each
HTTP step is captured into a trace (method, URL, request, response, status, ms) so the SE can
inspect the actual data. TLS verification is never disabled. Secrets are redacted: the gateway
password is never recorded, and the session token (X-chkp-sid) is masked.
"""
import os
import tempfile
import threading
import time
import uuid

import httpx

from ..config import get_settings
from ..db import SessionLocal
from ..models import DynamicLayer, LayerTask
from ..schemas.dynamic_layer import build_set_dynamic_content, evaluate_dynamic_content

GAIA_VERSION = "v1.9"
_MASK = "(session token masked)"

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


def _trace_entry(step, method, url, *, headers=None, body=None, resp=None, err=None, ms=None) -> dict:
    entry = {"step": step, "method": method, "url": url,
             "request": {"headers": headers or {}, "body": body},
             "status": (resp.status_code if resp is not None else None), "ms": ms}
    if err is not None:
        entry["response"] = {"error": str(err)}
    elif resp is not None:
        try:
            entry["response"] = resp.json()
        except Exception:
            entry["response"] = (resp.text or "")[:4000]
    else:
        entry["response"] = None
    return entry


def _task_details(result: dict) -> dict:
    return {
        "change-summary": result.get("change_summary", {}),
        "validation-warnings": result.get("validation_warnings", []),
        "validation-errors": result.get("validation_errors", []),
        "dry-run": result.get("dry_run", False),
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
    p.update(stage="done", status=status, task_id=task_id, summary=_summary(result),
             trace=result.get("trace", []))
    if result.get("validation_errors"):
        p["error"] = result["validation_errors"][0].get("message", "")


def start_apply(*, layer_id: int, target: str, dry_run: bool, gateway_host: str | None = None,
                gateway_port: int = 443, user: str | None = None, password: str | None = None,
                cert_pem: str | None = None) -> str:
    pid = uuid.uuid4().hex
    _PROGRESS[pid] = {"stage": "queued", "status": "running", "target": target,
                      "done_stages": [], "task_id": None, "summary": None, "error": None, "trace": []}
    threading.Thread(
        target=_run, args=(pid,),
        kwargs=dict(layer_id=layer_id, target=target, dry_run=dry_run, gateway_host=gateway_host,
                    gateway_port=gateway_port, user=user, password=password, cert_pem=cert_pem),
        daemon=True,
    ).start()
    return pid


def _run_mock(pid, payload, dry_run):
    """In-process mock: step the stages and synthesize a realistic request/response trace."""
    base = get_settings().base_url.rstrip("/") + f"/gaia_api/{GAIA_VERSION}"
    trace = []
    _advance(pid, "connecting"); time.sleep(0.3)
    _advance(pid, "logging_in"); time.sleep(0.3)
    trace.append(_trace_entry("login", "POST", f"{base}/login",
        headers={"Content-Type": "application/json"},
        body={"user": "<mock>", "password": "***"}, resp=None, ms=4))
    trace[-1]["status"] = 200
    trace[-1]["response"] = {"sid": _MASK, "session-timeout": 600}
    _advance(pid, "pushing"); time.sleep(0.35)
    result = evaluate_dynamic_content(payload)
    result["dry_run"] = dry_run
    task_id = uuid.uuid4().hex
    trace.append({"step": "set-dynamic-content", "method": "POST", "url": f"{base}/set-dynamic-content",
        "request": {"headers": {"Content-Type": "application/json", "X-chkp-sid": _MASK}, "body": payload},
        "status": 200, "ms": 6, "response": {"task-id": task_id}})
    _advance(pid, "polling"); time.sleep(0.3)
    show = {"tasks": [{"task-id": task_id, "task-name": "/set-dynamic-content",
            "status": result["status"], "status-code": result["status_code"],
            "progress-percentage": 100, "task-details": [_task_details(result)]}]}
    trace.append({"step": "show-task", "method": "POST", "url": f"{base}/show-task",
        "request": {"headers": {"X-chkp-sid": _MASK}, "body": {"task-id": task_id}},
        "status": 200, "ms": 5, "response": show})
    _advance(pid, "logging_out"); time.sleep(0.25)
    trace.append({"step": "logout", "method": "POST", "url": f"{base}/logout",
        "request": {"headers": {"X-chkp-sid": _MASK}, "body": None},
        "status": 200, "ms": 3, "response": {"message": "Session ended."}})
    result["trace"] = trace
    return result, result["status"], result["status_code"], task_id


def _run_gateway(pid, payload, dry_run, *, host, port, user, password, cert_pem):
    verify: bool | str = True
    cert_file = None
    if cert_pem and cert_pem.strip():
        cert_file = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        cert_file.write(cert_pem); cert_file.close(); verify = cert_file.name
    base = f"https://{host}:{port}/gaia_api/{GAIA_VERSION}"
    trace = []
    result = {"change_summary": {}, "validation_warnings": [], "validation_errors": [], "dry_run": dry_run}
    status, status_code, task_id = "failed", 0, ""
    try:
        with httpx.Client(verify=verify, timeout=30.0) as client:
            _advance(pid, "connecting")
            t = time.perf_counter()
            login = client.post(f"{base}/login", json={"user": user, "password": password})
            trace.append(_trace_entry("login", "POST", f"{base}/login",
                headers={"Content-Type": "application/json"},
                body={"user": user, "password": "***"}, resp=login, ms=round((time.perf_counter() - t) * 1000)))
            login.raise_for_status()
            sid = login.json().get("sid")
            _advance(pid, "logging_in")
            headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
            shown_headers = {"X-chkp-sid": _MASK, "Content-Type": "application/json"}
            try:
                _advance(pid, "pushing")
                t = time.perf_counter()
                resp = client.post(f"{base}/set-dynamic-content", json=payload, headers=headers)
                trace.append(_trace_entry("set-dynamic-content", "POST", f"{base}/set-dynamic-content",
                    headers=shown_headers, body=payload, resp=resp, ms=round((time.perf_counter() - t) * 1000)))
                status_code = resp.status_code
                task_id = (resp.json() or {}).get("task-id", "")
                _advance(pid, "polling")
                details = {}
                if task_id:
                    for _ in range(20):
                        t = time.perf_counter()
                        tr = client.post(f"{base}/show-task", json={"task-id": task_id}, headers=headers)
                        tasks = (tr.json() or {}).get("tasks", [])
                        finished = bool(tasks) and tasks[0].get("status") in ("succeeded", "failed")
                        if finished:
                            trace.append(_trace_entry("show-task", "POST", f"{base}/show-task",
                                headers=shown_headers, body={"task-id": task_id}, resp=tr,
                                ms=round((time.perf_counter() - t) * 1000)))
                            t0 = tasks[0]
                            details = (t0.get("task-details") or [{}])[0]
                            status = t0.get("status", "failed")
                            status_code = t0.get("status-code", status_code)
                            break
                        time.sleep(0.4)
                result = {"change_summary": details.get("change-summary", {}),
                          "validation_warnings": details.get("validation-warnings", []),
                          "validation_errors": details.get("validation-errors", []), "dry_run": dry_run}
            finally:
                _advance(pid, "logging_out")
                try:
                    t = time.perf_counter()
                    lo = client.post(f"{base}/logout", headers=headers)
                    trace.append(_trace_entry("logout", "POST", f"{base}/logout",
                        headers=shown_headers, body=None, resp=lo, ms=round((time.perf_counter() - t) * 1000)))
                except Exception:
                    pass
    except httpx.ConnectError as exc:
        trace.append(_trace_entry("connect", "POST", f"{base}/login", err=exc))
        result["validation_errors"] = [{"layer": "", "rule": "", "object": "",
            "message": "Could not reach the gateway, or TLS verification failed — use "
                       f"'Fetch & trust certificate' to pin a self-signed gateway: {exc}"}]
    except Exception as exc:
        trace.append(_trace_entry("error", "POST", base, err=exc))
        result["validation_errors"] = [{"layer": "", "rule": "", "object": "", "message": f"Gateway request failed: {exc}"}]
    finally:
        if cert_file:
            try:
                os.unlink(cert_file.name)
            except OSError:
                pass
    result["trace"] = trace
    return result, status, status_code, task_id


def _run(pid, *, layer_id, target, dry_run, gateway_host, gateway_port, user, password, cert_pem):
    db = SessionLocal()
    try:
        layer = db.get(DynamicLayer, layer_id)
        if layer is None:
            _PROGRESS[pid].update(stage="done", status="failed", error="Layer not found.")
            return
        payload = build_set_dynamic_content(layer, dry_run=dry_run)
        if target == "mock":
            result, status, status_code, task_id = _run_mock(pid, payload, dry_run)
        else:
            result, status, status_code, task_id = _run_gateway(
                pid, payload, dry_run, host=gateway_host, port=gateway_port,
                user=user, password=password, cert_pem=cert_pem)
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
