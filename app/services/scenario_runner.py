"""Server-side timed runner for scenario presets.

The whole point of pacing is that the SE clicks *Run*, then switches to SmartConsole to watch policy
follow — so the timer must live on the server, not in the browser. Each run is an in-memory record
(safe here: the app runs a single uvicorn worker) driven by an asyncio task that applies one step,
sleeps ``interval`` seconds, applies the next, and so on. Every step opens its own short-lived DB
session and commits ``dc.content`` so CloudGuard's next ~30s poll re-resolves the affected objects.

A run is keyed by ``dc_id`` (one active run per data center); starting a new one cancels the old. The
timeline UI polls :func:`get_run` for live status. State is process-local and intentionally ephemeral
— a restart drops in-flight runs, which is fine for a seconds-to-minutes demo.
"""
import asyncio
import datetime as dt

from ..db import SessionLocal
from ..models import Datacenter
from . import scenarios

_RUNS: dict[int, dict] = {}


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def get_run(dc_id: int) -> dict | None:
    return _RUNS.get(dc_id)


def _apply_step(dc_id: int, step: dict) -> None:
    """Apply one step in its own session/transaction (runs in a worker thread)."""
    with SessionLocal() as db:
        dc = db.get(Datacenter, dc_id)
        if dc is None:
            raise ValueError("data center no longer exists")
        new, _ = scenarios.apply_action(
            dc.provider, dc.content, step["action"],
            name=step.get("name", ""), value=step.get("value", ""), ip=step.get("ip", ""))
        dc.content = new
        db.commit()


async def _drive(dc_id: int, interval: int) -> None:
    run = _RUNS[dc_id]
    try:
        for i, step in enumerate(run["steps"]):
            if run["status"] != "running":
                break
            if i > 0 and interval > 0:
                await asyncio.sleep(interval)
            try:
                await asyncio.to_thread(_apply_step, dc_id, step)
                step["status"] = "done"
            except Exception as exc:           # one bad step shouldn't abort the rest of the demo
                step["status"] = "error"
                step["detail"] = str(exc)
            step["at"] = _now_iso()
        if run["status"] == "running":
            run["status"] = "done"
    except asyncio.CancelledError:
        run["status"] = "stopped"
    finally:
        run["task"] = None
        run["finished_at"] = _now_iso()


def start_run(dc_id: int, dc_name: str, label: str, steps: list[dict], interval: int) -> dict:
    """Begin (or replace) the run for ``dc_id`` and schedule the driver on the event loop."""
    old = _RUNS.get(dc_id)
    if old and old.get("task"):
        old["task"].cancel()
    run = {
        "dc_id": dc_id, "dc_name": dc_name, "label": label, "interval": interval,
        "status": "running", "started_at": _now_iso(), "finished_at": None, "task": None,
        "steps": [{"action": s["action"], "name": s.get("name", ""), "value": s.get("value", ""),
                   "ip": s.get("ip", ""), "desc": s.get("desc", s["action"]),
                   "status": "pending", "at": None} for s in steps],
    }
    _RUNS[dc_id] = run
    run["task"] = asyncio.create_task(_drive(dc_id, interval))
    return run


def stop_run(dc_id: int) -> bool:
    """Cancel a running scenario; remaining steps are left untouched. Returns True if one was running."""
    run = _RUNS.get(dc_id)
    if not run or run["status"] != "running":
        return False
    run["status"] = "stopped"
    if run.get("task"):
        run["task"].cancel()
        run["task"] = None
    return True
