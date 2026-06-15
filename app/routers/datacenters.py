"""Datacenters UI: author a mock cloud's inventory and get the SmartConsole connection details.
Currently OpenStack (Keystone + Nova + Neutron); other providers follow the same pattern."""
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Datacenter, User
from ..security import get_user_or_none, new_feed_token
from ..services import openstack as os_mock
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)

DEFAULT_INSTANCES = "web-1 = 10.0.0.11 | web, prod\nweb-2 = 10.0.0.12 | web, prod\ndb-1 = 10.0.0.21 | db, prod"
DEFAULT_SUBNETS = "app-subnet = 10.0.0.0/24"
DEFAULT_SECGROUPS = "web-sg\ndb-sg"


def _owned(db: Session, dc_id: int, user: User) -> Datacenter:
    dc = db.get(Datacenter, dc_id)
    if dc is None or dc.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Datacenter not found")
    return dc


def parse_instances(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        tags = []
        if "|" in line:
            line, tagpart = (p.strip() for p in line.split("|", 1))
            tags = [t.strip() for t in tagpart.split(",") if t.strip()]
        if "=" not in line:
            raise ValueError(f"Instance line must be 'name = ip': {raw.strip()!r}")
        name, ip = (p.strip() for p in line.split("=", 1))
        if not name or not ip:
            raise ValueError(f"Instance needs a name and an IP: {raw.strip()!r}")
        out.append({"name": name, "ip": ip, "tags": tags})
    return out


def parse_subnets(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Subnet line must be 'name = cidr': {raw.strip()!r}")
        name, cidr = (p.strip() for p in line.split("=", 1))
        out.append({"name": name, "cidr": cidr})
    return out


def parse_secgroups(text: str) -> list[dict]:
    return [{"name": ln.strip()} for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]


@router.get("/datacenters", response_class=HTMLResponse)
def dc_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dcs = db.scalars(
        select(Datacenter).where(Datacenter.owner_id == user.id).order_by(Datacenter.created_at.desc())
    ).all()
    rows = [{"dc": d,
             "instances": len(d.content.get("instances", []) or []),
             "subnets": len(d.content.get("subnets", []) or []),
             "secgroups": len(d.content.get("security_groups", []) or [])} for d in dcs]
    return templates.TemplateResponse(request, "dc_list.html", {"rows": rows, "flash": _pop_flash(request)})


@router.get("/datacenters/new", response_class=HTMLResponse)
def dc_new(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new.html", {"error": None, "form": {
        "name": "OpenStack-lab", "description": "",
        "instances_text": DEFAULT_INSTANCES, "subnets_text": DEFAULT_SUBNETS, "secgroups_text": DEFAULT_SECGROUPS,
    }})


@router.post("/datacenters/new")
def dc_create(request: Request, name: str = Form(...), description: str = Form(""),
              instances_text: str = Form(""), subnets_text: str = Form(""),
              secgroups_text: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        content = {
            "instances": parse_instances(instances_text),
            "subnets": parse_subnets(subnets_text),
            "security_groups": parse_secgroups(secgroups_text),
        }
        if not (content["instances"] or content["subnets"] or content["security_groups"]):
            raise ValueError("Add at least one instance, subnet, or security group.")
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new.html", {"error": str(exc), "form": {
            "name": name, "description": description, "instances_text": instances_text,
            "subnets_text": subnets_text, "secgroups_text": secgroups_text,
        }}, status_code=400)
    dc = Datacenter(token=new_feed_token(), provider="openstack", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"OpenStack datacenter “{name}” saved.")
    return RedirectResponse(f"/datacenters/{dc.id}", status_code=303)


@router.get("/datacenters/{dc_id}", response_class=HTMLResponse)
def dc_detail(dc_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    base = get_settings().base_url.rstrip("/")
    keystone_url = f"{base}/openstack/{dc.token}/v3"
    preview = {
        "nova /servers/detail": os_mock.nova_servers(dc),
        "neutron /subnets": os_mock.neutron_subnets(dc),
        "neutron /security-groups": os_mock.neutron_security_groups(dc),
    }
    return templates.TemplateResponse(request, "dc_detail.html", {
        "dc": dc, "keystone_url": keystone_url,
        "instances": dc.content.get("instances", []) or [],
        "subnets": dc.content.get("subnets", []) or [],
        "secgroups": dc.content.get("security_groups", []) or [],
        "preview_json": json.dumps(preview, indent=2),
        "flash": _pop_flash(request),
    })


@router.post("/datacenters/{dc_id}/delete")
def dc_delete(dc_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    name = dc.name
    db.delete(dc)
    db.commit()
    _flash(request, f"Datacenter “{name}” deleted.")
    return RedirectResponse("/datacenters", status_code=303)
