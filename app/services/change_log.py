"""Audit + rollback store for access-automation changes PUBLISHED to a live policy.

``record()`` is called by the apply / remove surfaces (UI router, ServiceNow webhook, MCP tools) AFTER a
successful publish. It saves the precomputed INVERSE op(s) the engine emitted, so ``revert()`` can surgically
undo exactly that one change in a single publish — no full-DB revision rollback, no touching the rest of the
policy. Dry-runs (publish=false) are never recorded: nothing was committed, so there is nothing to roll back.

Objects a change created (hosts / networks / services) are intentionally NOT deleted on revert — by then they
may be referenced by other rules, and removing them is a separate, riskier action — only the rule change is
undone (delete the added rule / re-enable the disabled rule / remove the widened object from the cell)."""
from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import AppliedChange


def _summary(action: str, outcome: str, req: dict) -> str:
    """A human one-liner for the history list, e.g. 'create: allow 10.1.2.250 -> Facebook'."""
    src = req.get("source") or "?"
    app = req.get("application")
    svc = req.get("service") or (f"{req.get('protocol', 'tcp')}/{req.get('port')}" if req.get("port") else None)
    dst = req.get("destination") or "Any"
    target = app or (f"{dst}:{svc}" if svc else dst)
    verb = {"create": "allow", "widen": "widen-allow", "disable": "revoke", "deny": "revoke"}.get(outcome, outcome)
    return f"{verb} {src} -> {target}"


def snapshot_request(req) -> dict:
    """Plain-data view of an AccessRequest, for the webhook / MCP surfaces (they hold the request OBJECT,
    not the raw form fields). Duck-typed — no engine import."""
    ip_src = getattr(req, "src_kind", "ip") == "ip"
    ip_dst = getattr(req, "dst_kind", "ip") == "ip"
    src = ", ".join(getattr(req, "src_cidrs", []) or []) if ip_src else getattr(req, "src_value", "")
    dst = ", ".join(getattr(req, "dst_cidrs", []) or []) if ip_dst else getattr(req, "dst_value", "")
    return {"source": src or "?", "destination": dst or "Any",
            "protocol": getattr(req, "protocol", "tcp"), "port": getattr(req, "ports", ""),
            "service": getattr(req, "service", None), "application": getattr(req, "application", None),
            "source_kind": getattr(req, "src_kind", "ip"), "destination_kind": getattr(req, "dst_kind", "ip")}


def record(db: Session, *, server, result: dict, request: dict, layer: str,
           package: Optional[str] = None, ticket_id: str = "", actor: str = "") -> Optional[AppliedChange]:
    """Persist a PUBLISHED change so it can be rolled back. No-op (returns None) unless the change actually
    committed and the engine handed back an inverse op-list — i.e. only real applies/removes are recorded,
    never dry-runs, no-ops, or reviews. ``request`` is the plain request tuple (for display); ``result`` is
    the engine's return dict (carries ``outcome``, ``inverse``, and the resolved object names)."""
    if not (result.get("ok") and result.get("published") and result.get("inverse")):
        return None
    outcome = result.get("outcome", "")
    action = result.get("action", "apply")           # remove_execute stamps action="remove"; apply omits it
    objs = [o for o in (result.get("source_object"), result.get("destination_object"),
                        result.get("service_object"), result.get("widen_object")) if o]
    row = AppliedChange(
        created_by=actor or "",
        server_id=getattr(server, "id", None),
        server_name=getattr(server, "name", "") or "",
        layer=layer or "",
        package=package,
        action=action,
        outcome=outcome,
        summary=_summary(action, outcome, request),
        ticket_id=(ticket_id or "").strip(),
        request_json=request,
        inverse_json=list(result.get("inverse") or []),
        objects_json=objs,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def recent(db: Session, limit: int = 50) -> list[AppliedChange]:
    """Most-recent changes first (the history list / 'undo last' is just the first un-reverted row)."""
    return list(db.scalars(select(AppliedChange).order_by(AppliedChange.created_at.desc()).limit(limit)))


def recent_for_server(db: Session, server_id: int, limit: int = 25) -> list[AppliedChange]:
    """Most-recent changes first for ONE management server (the per-server access-automation page panel)."""
    return list(db.scalars(select(AppliedChange).where(AppliedChange.server_id == server_id)
                           .order_by(AppliedChange.created_at.desc()).limit(limit)))


def get(db: Session, change_id: int) -> Optional[AppliedChange]:
    return db.get(AppliedChange, change_id)


def _safe_commit(db: Session) -> bool:
    """Commit best-effort — a bookkeeping write must NEVER turn an already-committed SMS revert into a
    reported failure. Rolls back + logs on error; returns whether it stuck."""
    try:
        db.commit()
        return True
    except Exception:  # noqa: BLE001
        import logging
        logging.getLogger("dcsim.change_log").exception("change-log status write failed")
        try:
            db.rollback()
        except Exception:  # noqa: BLE001
            pass
        return False


def mark_reverted(db: Session, change: AppliedChange, actor: str = "") -> None:
    change.reverted_at = dt.datetime.now(dt.timezone.utc)
    change.reverted_by = actor or ""
    change.revert_error = ""
    _safe_commit(db)


def mark_revert_failed(db: Session, change: AppliedChange, error: str) -> None:
    change.revert_error = (error or "")[:2000]
    _safe_commit(db)
