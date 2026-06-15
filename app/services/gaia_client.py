"""Apply a Dynamic Layer to a REAL gateway via the Gaia API: login -> set-dynamic-content
-> poll show-task -> logout.

Security:
- TLS verification stays ON (org policy forbids disabling it). Gateways usually have a
  self-signed cert, so the SE may paste the gateway's PEM to pin/trust it; without a trusted
  cert the request fails with a clear message rather than silently skipping verification.
- The gateway password is used only for this call and never persisted or logged.
"""
import os
import tempfile
import time
import uuid

import httpx

from ..models import DynamicLayer, LayerTask
from ..schemas.dynamic_layer import build_set_dynamic_content

GAIA_VERSION = "v1.9"


def apply_to_gateway(
    db,
    layer: DynamicLayer,
    *,
    host: str,
    port: int = 443,
    user: str,
    password: str,
    dry_run: bool = False,
    cert_pem: str | None = None,
    gaia_version: str = GAIA_VERSION,
) -> LayerTask:
    payload = build_set_dynamic_content(layer, dry_run=dry_run)
    base = f"https://{host}:{port}/gaia_api/{gaia_version}"

    # TLS: verify against a provided PEM (pinned), otherwise the system trust store. Never off.
    verify: bool | str = True
    cert_file = None
    if cert_pem and cert_pem.strip():
        cert_file = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        cert_file.write(cert_pem)
        cert_file.close()
        verify = cert_file.name

    result: dict = {"change_summary": {}, "validation_warnings": [], "validation_errors": [], "dry_run": dry_run}
    status, status_code, task_id = "failed", 0, ""
    try:
        with httpx.Client(verify=verify, timeout=30.0) as client:
            login = client.post(f"{base}/login", json={"user": user, "password": password})
            login.raise_for_status()
            sid = login.json().get("sid")
            headers = {"X-chkp-sid": sid, "Content-Type": "application/json"}
            try:
                resp = client.post(f"{base}/set-dynamic-content", json=payload, headers=headers)
                status_code = resp.status_code
                task_id = (resp.json() or {}).get("task-id", "")
                details: dict = {}
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
                        time.sleep(0.5)
                result = {
                    "change_summary": details.get("change-summary", {}),
                    "validation_warnings": details.get("validation-warnings", []),
                    "validation_errors": details.get("validation-errors", []),
                    "dry_run": dry_run,
                }
            finally:
                try:
                    client.post(f"{base}/logout", headers=headers)
                except Exception:
                    pass
    except httpx.ConnectError as exc:
        result["validation_errors"] = [{"layer": "", "rule": "", "object": "",
            "message": f"Could not reach the gateway, or TLS verification failed "
                       f"(paste the gateway certificate to pin it): {exc}"}]
    except Exception as exc:
        result["validation_errors"] = [{"layer": "", "rule": "", "object": "",
            "message": f"Gateway request failed: {exc}"}]
    finally:
        if cert_file:
            try:
                os.unlink(cert_file.name)
            except OSError:
                pass

    task = LayerTask(
        task_id=task_id or str(uuid.uuid4()),
        layer_id=layer.id,
        target="gateway",
        gateway_host=host,
        dry_run=dry_run,
        status=status,
        status_code=status_code,
        result=result,
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task
