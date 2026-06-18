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


DEFAULT_ACI_EPGS = "web-epg = 10.30.0.11, 10.30.0.12\napp-epg = 10.30.0.21\ndb-epg = 10.30.0.31"
DEFAULT_ACI_ESGS = "prod-esg = 10.30.0.11, 10.30.0.21, 10.30.0.31\nweb-esg = 10.30.0.11, 10.30.0.12"


def parse_aci_groups(text: str) -> list[dict]:
    """ACI EPG/ESG quick-entry: 'GroupName = ip1, ip2, …' per line → {name, ips}."""
    out = []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        name, _, rest = ln.partition("=")
        name = name.strip()
        if not name:
            continue
        out.append({"name": name, "ips": [p.strip() for p in rest.split(",") if p.strip()]})
    return out


@router.get("/datacenters/new/aci", response_class=HTMLResponse)
def dc_new_aci(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new_aci.html", {"error": None, "form": {
        "name": "Cisco-ACI-lab", "description": "", "tenant": "DCSIM", "app_profile": "DCSIM-AP",
        "epgs_text": DEFAULT_ACI_EPGS, "esgs_text": DEFAULT_ACI_ESGS, "aci_username": "admin",
    }})


@router.post("/datacenters/new/aci")
def dc_create_aci(request: Request, name: str = Form(...), description: str = Form(""),
                  tenant: str = Form("DCSIM"), app_profile: str = Form("DCSIM-AP"),
                  epgs_text: str = Form(""), esgs_text: str = Form(""),
                  aci_username: str = Form("admin"), aci_password: str = Form(""),
                  db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        content = {"tenant": (tenant or "DCSIM").strip(), "app_profile": (app_profile or "DCSIM-AP").strip(),
                   "epgs": parse_aci_groups(epgs_text), "esgs": parse_aci_groups(esgs_text)}
        if not (content["epgs"] or content["esgs"]):
            raise ValueError("Add at least one EPG or ESG.")
        if aci_password:  # validated at aaaLogin; stored only as a one-way hash
            content["auth"] = {"username": aci_username or "admin",
                               "password_hash": hash_password(aci_password)}
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new_aci.html", {"error": str(exc), "form": {
            "name": name, "description": description, "tenant": tenant, "app_profile": app_profile,
            "epgs_text": epgs_text, "esgs_text": esgs_text, "aci_username": aci_username,
        }}, status_code=400)
    dc = Datacenter(token=new_feed_token(), provider="aci", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"Cisco ACI datacenter “{name}” saved.")
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
        elif d.provider == "aci":
            summary = f"{len(c.get('epgs', []) or [])} EPG(s) · {len(c.get('esgs', []) or [])} ESG(s)"
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
    if dc.provider == "aci":
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "aci_url": base, "apex_host": apex_host,
            "tenant": (dc.content or {}).get("tenant") or "DCSIM",
            "app_profile": (dc.content or {}).get("app_profile") or "DCSIM-AP",
            "epgs": dc.content.get("epgs", []) or [], "esgs": dc.content.get("esgs", []) or [],
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
