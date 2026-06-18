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
from ..security import get_user_or_none, hash_password, new_feed_token
from ..services import openstack as os_mock
from .ui import _flash, _pop_flash, templates

router = APIRouter(include_in_schema=False)

DEFAULT_INSTANCES = ("web-1 = 10.0.0.11 | web-sg, prod-sg\nweb-2 = 10.0.0.12 | web-sg, prod-sg\n"
                     "db-1 = 10.0.0.21 | db-sg, prod-sg")
DEFAULT_SUBNETS = "app-subnet = 10.0.0.0/24"
DEFAULT_SECGROUPS = "web-sg\ndb-sg\nprod-sg\nmgmt-sg"


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


DEFAULT_VMS = "web-1 = 10.0.0.11 | web, prod\nweb-2 = 10.0.0.12 | web, prod\ndb-1 = 10.0.0.21 | db, prod"


def parse_vms(text: str) -> list[dict]:
    """vCenter VM quick-entry: 'name = ip | tag1, tag2' per line (power defaults to poweredOn)."""
    return [{"name": vm["name"], "ip": vm["ip"], "tags": vm["tags"],
             "power": "poweredOn", "guest_os": ""} for vm in parse_instances(text)]


# NSX-T tags are scope/value pairs, written here as 'scope=value' (bare 'value' = empty scope).
DEFAULT_NSXT_VMS = ("web-vm-01 = 10.10.20.5 | tier=web, env=prod\n"
                    "web-vm-02 = 10.10.20.6 | tier=web, env=prod\n"
                    "db-vm-01 = 10.10.30.5 | tier=db, env=prod")
DEFAULT_NSXT_GROUPS = "Web Servers = tier=web | env=production\nDB Servers = tier=db"


def parse_nsxt_groups(text: str) -> list[dict]:
    """NSX-T group quick-entry: 'GroupName = member_tag | grouptag1, grouptag2' per line.
    member_tag (a VM 'scope=value' tag) defines dynamic membership; the trailing tags are the
    group's own NSX-T tags."""
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        name, _, rest = ln.partition("=")
        name = name.strip()
        if not name:
            continue
        member, _, gtags = rest.partition("|")
        out.append({"name": name, "member_tag": member.strip(),
                    "tags": [t.strip() for t in gtags.split(",") if t.strip()]})
    return out


# Proxmox VE tags are flat (a ';'-joined string), so 'name = ip | tag, tag' reuses parse_instances.
DEFAULT_PROXMOX_VMS = ("web-1 = 10.20.0.11 | web, prod\nweb-2 = 10.20.0.12 | web, prod\n"
                       "db-1 = 10.20.0.21 | db, prod")


@router.get("/datacenters/new/proxmox", response_class=HTMLResponse)
def dc_new_proxmox(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new_proxmox.html", {"error": None, "form": {
        "name": "Proxmox-lab", "description": "", "vms_text": DEFAULT_PROXMOX_VMS,
        "node": "pve", "token_id": "root@pam!cloudguard",
    }})


@router.post("/datacenters/new/proxmox")
def dc_create_proxmox(request: Request, name: str = Form(...), description: str = Form(""),
                      vms_text: str = Form(""), node: str = Form("pve"),
                      token_id: str = Form(""), token_secret: str = Form(""),
                      db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        vms = parse_instances(vms_text)  # 'name = ip | tag, tag' — Proxmox tags are flat
        if not vms:
            raise ValueError("Add at least one VM.")
        content = {"vms": vms, "node": (node or "pve").strip()}
        # API token is validated on every call; the secret is stored only as a one-way hash.
        # Leave the secret blank for an open lab (the mock then accepts any/no token).
        if token_secret:
            content["auth"] = {"token_id": (token_id or "").strip(),
                               "secret_hash": hash_password(token_secret)}
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new_proxmox.html", {"error": str(exc), "form": {
            "name": name, "description": description, "vms_text": vms_text, "node": node,
            "token_id": token_id,
        }}, status_code=400)
    dc = Datacenter(token=new_feed_token(), provider="proxmox", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"Proxmox datacenter “{name}” saved.")
    return RedirectResponse(f"/datacenters/{dc.id}", status_code=303)


@router.get("/datacenters", response_class=HTMLResponse)
def dc_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dcs = db.scalars(
        select(Datacenter).where(Datacenter.owner_id == user.id).order_by(Datacenter.created_at.desc())
    ).all()
    rows = []
    for d in dcs:
        c = d.content or {}
        if d.provider in ("vcenter", "proxmox"):
            summary = f"{len(c.get('vms', []) or [])} VM(s)"
        elif d.provider in ("nsxt", "globalnsxt"):
            summary = f"{len(c.get('vms', []) or [])} VM(s) · {len(c.get('groups', []) or [])} group(s)"
        else:
            summary = (f"{len(c.get('instances', []) or [])} instance(s) · "
                       f"{len(c.get('subnets', []) or [])} subnet(s) · "
                       f"{len(c.get('security_groups', []) or [])} sec group(s)")
        rows.append({"dc": d, "summary": summary})
    return templates.TemplateResponse(request, "dc_list.html", {"rows": rows, "flash": _pop_flash(request)})


@router.get("/datacenters/new", response_class=HTMLResponse)
def dc_new(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new.html", {"error": None, "form": {
        "name": "OpenStack-lab", "description": "", "os_username": "admin", "os_project": "demo",
        "instances_text": DEFAULT_INSTANCES, "subnets_text": DEFAULT_SUBNETS, "secgroups_text": DEFAULT_SECGROUPS,
    }})


@router.post("/datacenters/new")
def dc_create(request: Request, name: str = Form(...), description: str = Form(""),
              instances_text: str = Form(""), subnets_text: str = Form(""),
              secgroups_text: str = Form(""), os_username: str = Form("admin"),
              os_password: str = Form(""), os_project: str = Form("demo"),
              db: Session = Depends(get_db)):
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
        # When a password is set, Keystone validates it (and the username) and 401s on mismatch.
        # The password is stored only as a one-way PBKDF2 hash; leave it blank for an open lab.
        if os_password:
            content["auth"] = {"username": os_username or "admin",
                               "password_hash": hash_password(os_password),
                               "project": os_project or "demo"}
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new.html", {"error": str(exc), "form": {
            "name": name, "description": description, "instances_text": instances_text,
            "subnets_text": subnets_text, "secgroups_text": secgroups_text,
            "os_username": os_username, "os_project": os_project,
        }}, status_code=400)
    dc = Datacenter(token=new_feed_token(), provider="openstack", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"OpenStack datacenter “{name}” saved.")
    return RedirectResponse(f"/datacenters/{dc.id}", status_code=303)


@router.get("/datacenters/new/vcenter", response_class=HTMLResponse)
def dc_new_vcenter(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new_vcenter.html", {"error": None, "form": {
        "name": "vCenter-lab", "description": "", "vms_text": DEFAULT_VMS, "vc_username": "administrator@vsphere.local",
    }})


@router.post("/datacenters/new/vcenter")
def dc_create_vcenter(request: Request, name: str = Form(...), description: str = Form(""),
                      vms_text: str = Form(""), vc_username: str = Form("administrator@vsphere.local"),
                      vc_password: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        vms = parse_vms(vms_text)
        if not vms:
            raise ValueError("Add at least one VM.")
        content = {"vms": vms}
        if vc_password:  # validated on the SOAP Login; stored only as a one-way hash
            content["auth"] = {"username": vc_username or "administrator@vsphere.local",
                               "password_hash": hash_password(vc_password)}
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new_vcenter.html", {"error": str(exc), "form": {
            "name": name, "description": description, "vms_text": vms_text, "vc_username": vc_username,
        }}, status_code=400)
    dc = Datacenter(token=new_feed_token(), provider="vcenter", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"vCenter datacenter “{name}” saved.")
    return RedirectResponse(f"/datacenters/{dc.id}", status_code=303)


@router.get("/datacenters/new/nsxt", response_class=HTMLResponse)
def dc_new_nsxt(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new_nsxt.html", {"error": None, "form": {
        "name": "NSX-T-lab", "description": "", "vms_text": DEFAULT_NSXT_VMS,
        "groups_text": DEFAULT_NSXT_GROUPS, "nsxt_username": "admin",
    }})


@router.post("/datacenters/new/nsxt")
def dc_create_nsxt(request: Request, name: str = Form(...), description: str = Form(""),
                   vms_text: str = Form(""), groups_text: str = Form(""),
                   nsxt_username: str = Form("admin"), nsxt_password: str = Form(""),
                   db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        content = {"vms": parse_instances(vms_text), "groups": parse_nsxt_groups(groups_text)}
        if not (content["vms"] or content["groups"]):
            raise ValueError("Add at least one VM or group.")
        if nsxt_password:  # validated at session/login time; stored only as a one-way hash
            content["auth"] = {"username": nsxt_username or "admin",
                               "password_hash": hash_password(nsxt_password)}
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new_nsxt.html", {"error": str(exc), "form": {
            "name": name, "description": description, "vms_text": vms_text,
            "groups_text": groups_text, "nsxt_username": nsxt_username,
        }}, status_code=400)
    dc = Datacenter(token=new_feed_token(), provider="nsxt", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"NSX-T datacenter “{name}” saved.")
    return RedirectResponse(f"/datacenters/{dc.id}", status_code=303)


@router.get("/datacenters/new/globalnsxt", response_class=HTMLResponse)
def dc_new_globalnsxt(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new_globalnsxt.html", {"error": None, "form": {
        "name": "Global-NSX-T-lab", "description": "", "vms_text": DEFAULT_NSXT_VMS,
        "groups_text": DEFAULT_NSXT_GROUPS, "nsxt_username": "admin",
    }})


@router.post("/datacenters/new/globalnsxt")
def dc_create_globalnsxt(request: Request, name: str = Form(...), description: str = Form(""),
                         vms_text: str = Form(""), groups_text: str = Form(""),
                         nsxt_username: str = Form("admin"), nsxt_password: str = Form(""),
                         db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        # Same data model as NSX-T (VMs + NS Groups); the Global Manager just serves it at a
        # different policy path. parse_instances/parse_nsxt_groups are shared.
        content = {"vms": parse_instances(vms_text), "groups": parse_nsxt_groups(groups_text)}
        if not (content["vms"] or content["groups"]):
            raise ValueError("Add at least one VM or group.")
        if nsxt_password:
            content["auth"] = {"username": nsxt_username or "admin",
                               "password_hash": hash_password(nsxt_password)}
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new_globalnsxt.html", {"error": str(exc), "form": {
            "name": name, "description": description, "vms_text": vms_text,
            "groups_text": groups_text, "nsxt_username": nsxt_username,
        }}, status_code=400)
    dc = Datacenter(token=new_feed_token(), provider="globalnsxt", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"Global NSX-T datacenter “{name}” saved.")
    return RedirectResponse(f"/datacenters/{dc.id}", status_code=303)


@router.get("/datacenters/{dc_id}", response_class=HTMLResponse)
def dc_detail(dc_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    base = get_settings().base_url.rstrip("/")
    apex_host = base.split("://", 1)[-1]  # bare host SmartConsole enters for vCenter/NSX-T
    if dc.provider == "vcenter":
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "apex_host": apex_host,
            "vms": dc.content.get("vms", []) or [], "dc_auth": (dc.content or {}).get("auth") or {},
            "flash": _pop_flash(request),
        })
    if dc.provider in ("nsxt", "globalnsxt"):
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "apex_host": apex_host,
            "vms": dc.content.get("vms", []) or [], "groups": dc.content.get("groups", []) or [],
            "dc_auth": (dc.content or {}).get("auth") or {}, "flash": _pop_flash(request),
        })
    if dc.provider == "proxmox":
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "apex_host": apex_host,
            "vms": dc.content.get("vms", []) or [], "node": (dc.content or {}).get("node") or "pve",
            "dc_auth": (dc.content or {}).get("auth") or {}, "flash": _pop_flash(request),
        })
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
        "os_auth": (dc.content or {}).get("auth") or {},
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
