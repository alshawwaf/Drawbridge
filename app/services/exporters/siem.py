"""Export builder: the SIEM receiver log (every received Log Exporter line, newest first).

Not owner-scoped — logs arrive from gateways like the ActivityLog, so the page (and this
export) shows all rows. The page's Format filter is client-side, so the export is the full set.
"""
from sqlalchemy import select

from ...models import SiemLog
from ..exporting import ExportTable, fmt_dt, register


@register("siem")
def build(db, user, qp) -> ExportTable:
    rows = db.scalars(
        select(SiemLog).order_by(SiemLog.at.desc(), SiemLog.id.desc())
    ).all()
    columns = ["Time (UTC)", "Source IP", "Transport", "Format", "Severity", "Host", "Summary"]
    data = [
        [
            fmt_dt(r.at),
            r.source_ip or "—",
            r.transport or "",
            (r.fmt or "").upper(),
            r.severity or "—",
            r.host or "—",
            r.summary or "—",
        ]
        for r in rows
    ]
    return ExportTable(
        title="SIEM receiver log",
        columns=columns,
        rows=data,
        subtitle="Log Exporter lines received by the built-in SIEM receiver, newest first.",
        meta=[("Records", str(len(data)))],
    )
