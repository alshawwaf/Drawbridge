"""Export builder: the Data Centers list (name, provider, inventory summary, created)."""
from sqlalchemy import select

from ...models import Datacenter
from ..exporting import ExportTable, fmt_dt, register


def _summary(dc: Datacenter) -> str:
    """The per-provider inventory summary string, mirroring dc_list's row build exactly."""
    c = dc.content or {}
    if dc.provider in ("vcenter", "proxmox"):
        return f"{len(c.get('vms', []) or [])} VM(s)"
    if dc.provider in ("nsxt", "globalnsxt"):
        return f"{len(c.get('vms', []) or [])} VM(s) · {len(c.get('groups', []) or [])} group(s)"
    if dc.provider == "aci":
        return f"{len(c.get('epgs', []) or [])} EPG(s) · {len(c.get('esgs', []) or [])} ESG(s)"
    if dc.provider == "kubernetes":
        return (f"{len(c.get('pods', []) or [])} pod(s) · {len(c.get('nodes', []) or [])} node(s) · "
                f"{len(c.get('services', []) or [])} service(s)")
    if dc.provider == "nutanix":
        ncats = sum(len(v.get("categories") or {}) for v in (c.get("vms", []) or []))
        return f"{len(c.get('vms', []) or [])} VM(s) · {ncats} category tag(s)"
    return (f"{len(c.get('instances', []) or [])} instance(s) · "
            f"{len(c.get('subnets', []) or [])} subnet(s) · "
            f"{len(c.get('security_groups', []) or [])} sec group(s)")


@register("datacenters")
def build(db, user, qp) -> ExportTable:
    dcs = db.scalars(
        select(Datacenter).where(Datacenter.owner_id == user.id).order_by(Datacenter.created_at.desc())
    ).all()

    columns = ["Name", "Provider", "Inventory", "Created"]
    data = [[d.name, d.provider, _summary(d), fmt_dt(d.created_at)] for d in dcs]

    return ExportTable(title="Data Centers", columns=columns, rows=data,
                       subtitle="Mock cloud/datacenter providers Check Point connects to.")
