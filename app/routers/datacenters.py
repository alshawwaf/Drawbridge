"""Datacenters UI: author a mock cloud's inventory and get the SmartConsole connection details.
Currently OpenStack (Keystone + Nova + Neutron); other providers follow the same pattern."""
import json

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Datacenter, User
from ..security import get_user_or_none, new_feed_token
from ..services import dc_creds
from ..services import kubernetes as k8s_svc
from ..services import nutanix as nutanix_svc
from ..services import openstack as os_mock
from ..services import table_prefs
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
        # API token is validated on every call; the secret is encrypted at rest (AES-GCM), or hashed
        # if encryption is unavailable. Leave it blank for an open lab (mock accepts any/no token).
        if token_secret:
            content["auth"] = {"token_id": (token_id or "").strip(),
                               **dc_creds.store("secret", token_secret)}
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
        if aci_password:  # validated at aaaLogin; encrypted at rest (AES-GCM), hashed if unavailable
            content["auth"] = {"username": aci_username or "admin",
                               **dc_creds.store("password", aci_password)}
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


# --- Kubernetes (kube-apiserver) ------------------------------------------------------------
# Pods/Services are namespaced ('namespace/name'); Nodes are cluster-scoped. Labels are a K8s map,
# entered as 'k=v, k=v'. Namespaces + the Label view are derived by CloudGuard from these.
DEFAULT_K8S_NODES = "node-1 = 10.40.0.11\nnode-2 = 10.40.0.12"
DEFAULT_K8S_PODS = ("production/web-7f9c = 10.40.1.11 | app=web, tier=frontend\n"
                    "production/web-8a2d = 10.40.1.12 | app=web, tier=frontend\n"
                    "production/api-5c3e = 10.40.1.21 | app=api, tier=backend\n"
                    "default/db-0 = 10.40.2.11 | app=postgres, tier=data")
DEFAULT_K8S_SERVICES = ("production/web-svc = 10.40.10.1 | LoadBalancer\n"
                        "production/api-svc = 10.40.10.2 | ClusterIP\n"
                        "default/db-svc = 10.40.10.11 | ClusterIP")


def parse_k8s_labels(text: str) -> dict:
    out = {}
    for kv in (text or "").split(","):
        kv = kv.strip()
        if not kv:
            continue
        k, _, v = kv.partition("=")
        out[k.strip()] = v.strip()
    return out


def _split_ref(ref: str) -> tuple[str, str]:
    """'namespace/name' → (namespace, name); a bare 'name' → ('default', name)."""
    ns, sep, name = ref.strip().partition("/")
    return (ns.strip(), name.strip()) if sep else ("default", ns.strip())


def parse_k8s_pods(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        labels = {}
        if "|" in ln:
            ln, lab = (p.strip() for p in ln.split("|", 1))
            labels = parse_k8s_labels(lab)
        if "=" not in ln:
            raise ValueError(f"Pod line must be 'namespace/name = ip': {raw.strip()!r}")
        ref, ip = (p.strip() for p in ln.split("=", 1))
        ns, name = _split_ref(ref)
        if not name or not ip:
            raise ValueError(f"Pod needs a name and an IP: {raw.strip()!r}")
        out.append({"namespace": ns, "name": name, "ip": ip, "labels": labels})
    return out


def parse_k8s_nodes(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        labels = {}
        if "|" in ln:
            ln, lab = (p.strip() for p in ln.split("|", 1))
            labels = parse_k8s_labels(lab)
        if "=" not in ln:
            raise ValueError(f"Node line must be 'name = ip': {raw.strip()!r}")
        name, ip = (p.strip() for p in ln.split("=", 1))
        if not name or not ip:
            raise ValueError(f"Node needs a name and an IP: {raw.strip()!r}")
        out.append({"name": name, "ip": ip, "labels": labels})
    return out


def parse_k8s_services(text: str) -> list[dict]:
    out = []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        svc_type = "ClusterIP"
        if "|" in ln:
            ln, t = (p.strip() for p in ln.split("|", 1))
            svc_type = t or "ClusterIP"
        if "=" not in ln:
            raise ValueError(f"Service line must be 'namespace/name = clusterIP': {raw.strip()!r}")
        ref, cip = (p.strip() for p in ln.split("=", 1))
        ns, name = _split_ref(ref)
        if not name:
            raise ValueError(f"Service needs a name: {raw.strip()!r}")
        out.append({"namespace": ns, "name": name, "cluster_ip": cip, "type": svc_type})
    return out


@router.get("/datacenters/new/kubernetes", response_class=HTMLResponse)
def dc_new_kubernetes(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new_kubernetes.html", {"error": None, "form": {
        "name": "Kubernetes-lab", "description": "", "nodes_text": DEFAULT_K8S_NODES,
        "pods_text": DEFAULT_K8S_PODS, "services_text": DEFAULT_K8S_SERVICES,
    }})


@router.post("/datacenters/new/kubernetes")
def dc_create_kubernetes(request: Request, name: str = Form(...), description: str = Form(""),
                         nodes_text: str = Form(""), pods_text: str = Form(""),
                         services_text: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        content = {"nodes": parse_k8s_nodes(nodes_text), "pods": parse_k8s_pods(pods_text),
                   "services": parse_k8s_services(services_text)}
        if not (content["nodes"] or content["pods"] or content["services"]):
            raise ValueError("Add at least one node, pod, or service.")
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new_kubernetes.html", {"error": str(exc), "form": {
            "name": name, "description": description, "nodes_text": nodes_text,
            "pods_text": pods_text, "services_text": services_text,
        }}, status_code=400)
    # The service-account token isn't entered here — the portal generates a downloadable one per DC
    # (see /datacenters/{id}/k8s-token) for SmartConsole's required token-file field; the mock is the
    # API server and accepts it.
    dc = Datacenter(token=new_feed_token(), provider="kubernetes", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"Kubernetes datacenter “{name}” saved.")
    return RedirectResponse(f"/datacenters/{dc.id}", status_code=303)


@router.get("/datacenters/{dc_id}/k8s-token")
def dc_k8s_token(dc_id: int, request: Request, db: Session = Depends(get_db)):
    """Download the datacenter's service-account token as a file, to import into SmartConsole's
    'Import Service Account Token…' field."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    if dc.provider != "kubernetes":
        raise HTTPException(status_code=404, detail="Not a Kubernetes datacenter")
    filename = f"{dc.name.replace(' ', '_')}-sa-token.txt"
    return Response(k8s_svc.sa_token(dc) + "\n", media_type="text/plain",
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.get("/datacenters/{dc_id}/k8s-ca")
def dc_k8s_ca(dc_id: int, request: Request, db: Session = Depends(get_db)):
    """Download the portal's TLS certificate chain (PEM), to import into SmartConsole's 'CA Certificate'
    field — the Kubernetes connector uses a custom trust store and won't trust the portal's cert
    otherwise (the TLS handshake fails before any HTTP)."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    if dc.provider != "kubernetes":
        raise HTTPException(status_code=404, detail="Not a Kubernetes datacenter")
    host = get_settings().base_url.split("://", 1)[-1].split("/")[0].split(":")[0]
    try:
        pem = k8s_svc.portal_tls_chain_pem(host)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Could not fetch the portal TLS chain: {exc}")
    return Response(pem, media_type="application/x-pem-file",
                    headers={"Content-Disposition": f'attachment; filename="{host}-ca.pem"'})


# --- Nutanix Prism --------------------------------------------------------------------------
# VMs carry Nutanix Categories (key=value, like tags), entered as 'name = ip | key=value, key=value'.
DEFAULT_NUTANIX_VMS = ("web-vm-1 = 10.50.0.11 | Environment=Production, AppType=Web\n"
                       "web-vm-2 = 10.50.0.12 | Environment=Production, AppType=Web\n"
                       "db-vm-1 = 10.50.0.21 | Environment=Production, AppType=Database")


def parse_nutanix_vms(text: str) -> list[dict]:
    """Nutanix VM quick-entry: 'name = ip | key=value, key=value' per line. The pipe part is the VM's
    applied Categories (Prism key/value pairs); reuses parse_k8s_labels for the 'k=v' map."""
    out = []
    for raw in text.splitlines():
        ln = raw.strip()
        if not ln or ln.startswith("#"):
            continue
        cats = {}
        if "|" in ln:
            ln, cpart = (p.strip() for p in ln.split("|", 1))
            cats = parse_k8s_labels(cpart)
        if "=" not in ln:
            raise ValueError(f"VM line must be 'name = ip': {raw.strip()!r}")
        name, ip = (p.strip() for p in ln.split("=", 1))
        if not name or not ip:
            raise ValueError(f"VM needs a name and an IP: {raw.strip()!r}")
        out.append({"name": name, "ip": ip, "categories": cats})
    return out


@router.get("/datacenters/new/nutanix", response_class=HTMLResponse)
def dc_new_nutanix(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "dc_new_nutanix.html", {"error": None, "form": {
        "name": "Nutanix-lab", "description": "", "vms_text": DEFAULT_NUTANIX_VMS,
        "nutanix_username": "admin",
    }})


@router.post("/datacenters/new/nutanix")
def dc_create_nutanix(request: Request, name: str = Form(...), description: str = Form(""),
                      vms_text: str = Form(""), nutanix_username: str = Form("admin"),
                      nutanix_password: str = Form(""), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        vms = parse_nutanix_vms(vms_text)
        if not vms:
            raise ValueError("Add at least one VM.")
        content = {"vms": vms}
        # Basic-auth credentials validated on every call; encrypted at rest (AES-GCM). Blank = open.
        if nutanix_password:
            content["auth"] = {"username": nutanix_username or "admin",
                               **dc_creds.store("password", nutanix_password)}
    except Exception as exc:
        return templates.TemplateResponse(request, "dc_new_nutanix.html", {"error": str(exc), "form": {
            "name": name, "description": description, "vms_text": vms_text,
            "nutanix_username": nutanix_username,
        }}, status_code=400)
    dc = Datacenter(token=new_feed_token(), provider="nutanix", name=name,
                    description=description, content=content, owner_id=user.id)
    db.add(dc)
    db.commit()
    db.refresh(dc)
    _flash(request, f"Nutanix datacenter “{name}” saved.")
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
        elif d.provider == "kubernetes":
            summary = (f"{len(c.get('pods', []) or [])} pod(s) · {len(c.get('nodes', []) or [])} node(s) · "
                       f"{len(c.get('services', []) or [])} service(s)")
        elif d.provider == "nutanix":
            ncats = sum(len(v.get("categories") or {}) for v in (c.get("vms", []) or []))
            summary = f"{len(c.get('vms', []) or [])} VM(s) · {ncats} category tag(s)"
        else:
            summary = (f"{len(c.get('instances', []) or [])} instance(s) · "
                       f"{len(c.get('subnets', []) or [])} subnet(s) · "
                       f"{len(c.get('security_groups', []) or [])} sec group(s)")
        rows.append({"dc": d, "summary": summary})
    return templates.TemplateResponse(request, "dc_list.html", {
        "rows": rows, "flash": _pop_flash(request),
        "cols": table_prefs.spec("datacenters"),
        "vis": table_prefs.visible_columns(db, user.id, "datacenters"),
    })


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
        # The password is encrypted at rest (AES-GCM); leave it blank for an open lab.
        if os_password:
            content["auth"] = {"username": os_username or "admin",
                               "project": os_project or "demo",
                               **dc_creds.store("password", os_password)}
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
        if vc_password:  # validated on the SOAP Login; encrypted at rest (AES-GCM)
            content["auth"] = {"username": vc_username or "administrator@vsphere.local",
                               **dc_creds.store("password", vc_password)}
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
        if nsxt_password:  # validated at session/login time; encrypted at rest (AES-GCM)
            content["auth"] = {"username": nsxt_username or "admin",
                               **dc_creds.store("password", nsxt_password)}
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
        if nsxt_password:  # encrypted at rest (AES-GCM)
            content["auth"] = {"username": nsxt_username or "admin",
                               **dc_creds.store("password", nsxt_password)}
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
    # Decrypt the stored secret (if any) so the detail page can show it as a copyable masked field.
    _auth = (dc.content or {}).get("auth") or {}
    dc_secret = dc_creds.plaintext(_auth, "secret" if dc.provider == "proxmox" else "password")
    if dc.provider == "vcenter":
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "apex_host": apex_host,
            "vms": (dc.content or {}).get("vms", []) or [], "dc_auth": _auth, "dc_secret": dc_secret,
            "flash": _pop_flash(request),
        })
    if dc.provider in ("nsxt", "globalnsxt"):
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "apex_host": apex_host,
            "vms": (dc.content or {}).get("vms", []) or [], "groups": (dc.content or {}).get("groups", []) or [],
            "dc_auth": _auth, "dc_secret": dc_secret, "flash": _pop_flash(request),
        })
    if dc.provider == "proxmox":
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "apex_host": apex_host,
            "vms": (dc.content or {}).get("vms", []) or [], "node": (dc.content or {}).get("node") or "pve",
            "dc_auth": _auth, "dc_secret": dc_secret, "flash": _pop_flash(request),
        })
    if dc.provider == "aci":
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "aci_url": base, "apex_host": apex_host,
            "tenant": (dc.content or {}).get("tenant") or "DCSIM",
            "app_profile": (dc.content or {}).get("app_profile") or "DCSIM-AP",
            "epgs": (dc.content or {}).get("epgs", []) or [], "esgs": (dc.content or {}).get("esgs", []) or [],
            "dc_auth": _auth, "dc_secret": dc_secret, "flash": _pop_flash(request),
        })
    if dc.provider == "kubernetes":
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "apex_host": apex_host,
            "nodes": (dc.content or {}).get("nodes", []) or [], "pods": (dc.content or {}).get("pods", []) or [],
            "services": (dc.content or {}).get("services", []) or [], "namespaces": k8s_svc.namespaces(dc),
            "dc_auth": _auth, "dc_secret": dc_secret, "flash": _pop_flash(request),
        })
    if dc.provider == "nutanix":
        return templates.TemplateResponse(request, "dc_detail.html", {
            "dc": dc, "apex_host": apex_host, "vms": (dc.content or {}).get("vms", []) or [],
            "categories": nutanix_svc.categories(dc),
            "dc_auth": _auth, "dc_secret": dc_secret, "flash": _pop_flash(request),
        })
    keystone_url = f"{base}/openstack/{dc.token}/v3"
    preview = {
        "nova /servers/detail": os_mock.nova_servers(dc),
        "neutron /subnets": os_mock.neutron_subnets(dc),
        "neutron /security-groups": os_mock.neutron_security_groups(dc),
    }
    return templates.TemplateResponse(request, "dc_detail.html", {
        "dc": dc, "keystone_url": keystone_url,
        "instances": (dc.content or {}).get("instances", []) or [],
        "subnets": (dc.content or {}).get("subnets", []) or [],
        "secgroups": (dc.content or {}).get("security_groups", []) or [],
        "os_auth": _auth, "dc_secret": dc_secret,
        "preview_json": json.dumps(preview, indent=2),
        "flash": _pop_flash(request),
    })


# --- Edit an existing datacenter -----------------------------------------------------------
# The create forms (dc_new_*.html) are reused for editing: the GET prefills them by serializing the
# stored content back into the quick-entry text format, the POST re-parses and updates in place.

def _ser_tagged(items: list[dict]) -> str:
    """'name = ip | tag, tag' — list-tag items (OpenStack instances; vCenter/NSX-T/Proxmox VMs)."""
    out = []
    for it in items or []:
        tags = ", ".join(it.get("tags") or [])
        out.append(f"{it['name']} = {it.get('ip', '')}" + (f" | {tags}" if tags else ""))
    return "\n".join(out)


def _ser_kvtagged(items: list[dict], key: str) -> str:
    """'name = ip | k=v, k=v' — dict-tag items (Nutanix 'categories'; K8s node 'labels')."""
    out = []
    for it in items or []:
        kv = ", ".join(f"{k}={v}" for k, v in (it.get(key) or {}).items())
        out.append(f"{it['name']} = {it.get('ip', '')}" + (f" | {kv}" if kv else ""))
    return "\n".join(out)


def _ser_subnets(items: list[dict]) -> str:
    return "\n".join(f"{s['name']} = {s.get('cidr', '')}" for s in items or [])


def _ser_secgroups(items: list[dict]) -> str:
    return "\n".join(s["name"] for s in items or [])


def _ser_nsxt_groups(items: list[dict]) -> str:
    out = []
    for g in items or []:
        gtags = ", ".join(g.get("tags") or [])
        out.append(f"{g['name']} = {g.get('member_tag', '')}" + (f" | {gtags}" if gtags else ""))
    return "\n".join(out)


def _ser_aci_groups(items: list[dict]) -> str:
    return "\n".join(f"{g['name']} = {', '.join(g.get('ips') or [])}" for g in items or [])


def _ser_k8s_pods(items: list[dict]) -> str:
    out = []
    for p in items or []:
        ref = f"{p.get('namespace', 'default')}/{p['name']}"
        kv = ", ".join(f"{k}={v}" for k, v in (p.get("labels") or {}).items())
        out.append(f"{ref} = {p.get('ip', '')}" + (f" | {kv}" if kv else ""))
    return "\n".join(out)


def _ser_k8s_services(items: list[dict]) -> str:
    out = []
    for s in items or []:
        ref = f"{s.get('namespace', 'default')}/{s['name']}"
        out.append(f"{ref} = {s.get('cluster_ip', '')} | {s.get('type', 'ClusterIP')}")
    return "\n".join(out)


def _edit_auth(content: dict, dc: Datacenter, raw, *, identity: dict, secret_form: str, secret_key: str):
    """Edit-mode credential handling, mirroring the gateway password UX: a blank secret keeps the one
    already stored, a new value re-encrypts, and 'clear_creds' drops auth (back to an open lab).
    ``identity`` maps form-field → auth-key for the non-secret fields stored alongside the secret."""
    if not secret_form or raw.get("clear_creds"):
        return
    ident = {akey: (raw.get(ff) or "").strip() for ff, akey in identity.items()}
    new_secret = (raw.get(secret_form) or "").strip()
    existing = (dc.content or {}).get("auth") or {}
    if new_secret:
        content["auth"] = {**ident, **dc_creds.store(secret_key, new_secret)}
    elif dc_creds.configured(existing, secret_key):
        content["auth"] = {**existing, **ident}  # keep the stored secret, refresh identity fields


_DC_EDIT_TEMPLATE = {
    "openstack": "dc_new.html", "vcenter": "dc_new_vcenter.html", "nsxt": "dc_new_nsxt.html",
    "globalnsxt": "dc_new_globalnsxt.html", "proxmox": "dc_new_proxmox.html", "aci": "dc_new_aci.html",
    "kubernetes": "dc_new_kubernetes.html", "nutanix": "dc_new_nutanix.html",
}

# Identity fields stored alongside the secret, with sensible defaults seeded when a password is first
# set on an open lab. Kubernetes is absent (no stored credential — it uses a generated SA token).
_DC_IDENTITY = {
    "openstack": {"username": "admin", "project": "demo"},
    "vcenter": {"username": "administrator@vsphere.local"},
    "nsxt": {"username": "admin"}, "globalnsxt": {"username": "admin"},
    "aci": {"username": "admin"}, "nutanix": {"username": "admin"},
    "proxmox": {"token_id": "root@pam!cloudguard"},
}


def _quick_set_secret(content: dict, provider: str, value: str, secret_key: str) -> None:
    """Inline password edit: a value (re)encrypts the secret — keeping existing identity fields or
    seeding provider defaults (so OpenStack's project / Proxmox's token-id survive) — while an empty
    value drops auth entirely (reverting to an open lab)."""
    auth = dict(content.get("auth") or {})
    if value:
        ident = {k: auth.get(k, dflt) for k, dflt in _DC_IDENTITY[provider].items()}
        content["auth"] = {**ident, **dc_creds.store(secret_key, value)}
    else:
        content.pop("auth", None)


def _dc_build_form(dc: Datacenter) -> dict:
    """Serialize a datacenter's content into the create-form's text fields (for prefill / re-render)."""
    c = dc.content or {}
    a = c.get("auth") or {}
    form = {"name": dc.name, "description": dc.description or ""}
    p = dc.provider
    if p == "openstack":
        form.update(instances_text=_ser_tagged(c.get("instances")), subnets_text=_ser_subnets(c.get("subnets")),
                    secgroups_text=_ser_secgroups(c.get("security_groups")),
                    os_username=a.get("username", "admin"), os_project=a.get("project", "demo"))
    elif p == "vcenter":
        form.update(vms_text=_ser_tagged(c.get("vms")), vc_username=a.get("username", "administrator@vsphere.local"))
    elif p in ("nsxt", "globalnsxt"):
        form.update(vms_text=_ser_tagged(c.get("vms")), groups_text=_ser_nsxt_groups(c.get("groups")),
                    nsxt_username=a.get("username", "admin"))
    elif p == "proxmox":
        form.update(vms_text=_ser_tagged(c.get("vms")), node=c.get("node", "pve"),
                    token_id=a.get("token_id", "root@pam!cloudguard"))
    elif p == "aci":
        form.update(tenant=c.get("tenant", "DCSIM"), app_profile=c.get("app_profile", "DCSIM-AP"),
                    epgs_text=_ser_aci_groups(c.get("epgs")), esgs_text=_ser_aci_groups(c.get("esgs")),
                    aci_username=a.get("username", "admin"))
    elif p == "kubernetes":
        form.update(nodes_text=_ser_kvtagged(c.get("nodes"), "labels"), pods_text=_ser_k8s_pods(c.get("pods")),
                    services_text=_ser_k8s_services(c.get("services")))
    elif p == "nutanix":
        form.update(vms_text=_ser_kvtagged(c.get("vms"), "categories"), nutanix_username=a.get("username", "admin"))
    return form


def _dc_parse_edit(dc: Datacenter, raw) -> dict:
    """Rebuild a datacenter's content dict from the submitted edit form (raises ValueError on bad input)."""
    p = dc.provider
    if p == "openstack":
        content = {"instances": parse_instances(raw.get("instances_text", "")),
                   "subnets": parse_subnets(raw.get("subnets_text", "")),
                   "security_groups": parse_secgroups(raw.get("secgroups_text", ""))}
        if not (content["instances"] or content["subnets"] or content["security_groups"]):
            raise ValueError("Add at least one instance, subnet, or security group.")
        _edit_auth(content, dc, raw, identity={"os_username": "username", "os_project": "project"},
                   secret_form="os_password", secret_key="password")
    elif p == "vcenter":
        vms = parse_vms(raw.get("vms_text", ""))
        prev = {v.get("name"): v for v in (dc.content or {}).get("vms", [])}
        for v in vms:                       # editing names/IPs/tags must not wipe stored power/guest_os
            old = prev.get(v["name"], {})
            v["power"], v["guest_os"] = old.get("power", v["power"]), old.get("guest_os", v["guest_os"])
        content = {"vms": vms}
        if not content["vms"]:
            raise ValueError("Add at least one VM.")
        _edit_auth(content, dc, raw, identity={"vc_username": "username"},
                   secret_form="vc_password", secret_key="password")
    elif p in ("nsxt", "globalnsxt"):
        content = {"vms": parse_instances(raw.get("vms_text", "")), "groups": parse_nsxt_groups(raw.get("groups_text", ""))}
        if not (content["vms"] or content["groups"]):
            raise ValueError("Add at least one VM or group.")
        _edit_auth(content, dc, raw, identity={"nsxt_username": "username"},
                   secret_form="nsxt_password", secret_key="password")
    elif p == "proxmox":
        content = {"vms": parse_instances(raw.get("vms_text", "")), "node": (raw.get("node") or "pve").strip()}
        if not content["vms"]:
            raise ValueError("Add at least one VM.")
        _edit_auth(content, dc, raw, identity={"token_id": "token_id"},
                   secret_form="token_secret", secret_key="secret")
    elif p == "aci":
        content = {"tenant": (raw.get("tenant") or "DCSIM").strip(),
                   "app_profile": (raw.get("app_profile") or "DCSIM-AP").strip(),
                   "epgs": parse_aci_groups(raw.get("epgs_text", "")), "esgs": parse_aci_groups(raw.get("esgs_text", ""))}
        if not (content["epgs"] or content["esgs"]):
            raise ValueError("Add at least one EPG or ESG.")
        _edit_auth(content, dc, raw, identity={"aci_username": "username"},
                   secret_form="aci_password", secret_key="password")
    elif p == "kubernetes":
        content = {"nodes": parse_k8s_nodes(raw.get("nodes_text", "")), "pods": parse_k8s_pods(raw.get("pods_text", "")),
                   "services": parse_k8s_services(raw.get("services_text", ""))}
        if not (content["nodes"] or content["pods"] or content["services"]):
            raise ValueError("Add at least one node, pod, or service.")
    elif p == "nutanix":
        content = {"vms": parse_nutanix_vms(raw.get("vms_text", ""))}
        if not content["vms"]:
            raise ValueError("Add at least one VM.")
        _edit_auth(content, dc, raw, identity={"nutanix_username": "username"},
                   secret_form="nutanix_password", secret_key="password")
    else:
        raise ValueError(f"This datacenter type ({p}) can't be edited.")
    return content


def _dc_edit_ctx(dc: Datacenter, form: dict, error: str | None) -> dict:
    secret_key = "secret" if dc.provider == "proxmox" else "password"
    return {"error": error, "form": form, "editing": True,
            "action": f"/datacenters/{dc.id}/edit", "cancel": f"/datacenters/{dc.id}",
            "creds_set": dc_creds.configured((dc.content or {}).get("auth") or {}, secret_key)}


@router.get("/datacenters/{dc_id}/edit", response_class=HTMLResponse)
def dc_edit(dc_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    tmpl = _DC_EDIT_TEMPLATE.get(dc.provider)
    if not tmpl:
        raise HTTPException(status_code=404, detail="This datacenter type can't be edited")
    return templates.TemplateResponse(request, tmpl, _dc_edit_ctx(dc, _dc_build_form(dc), None))


@router.post("/datacenters/{dc_id}/edit")
async def dc_edit_save(dc_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    dc = _owned(db, dc_id, user)
    tmpl = _DC_EDIT_TEMPLATE.get(dc.provider)
    if not tmpl:
        raise HTTPException(status_code=404, detail="This datacenter type can't be edited")
    raw = await request.form()
    name = (raw.get("name") or "").strip()
    try:
        if not name:
            raise ValueError("Name is required.")
        content = _dc_parse_edit(dc, raw)
    except Exception as exc:
        # Re-render with the values the user just submitted (passwords are never echoed back).
        form = {k: raw.get(k, v) for k, v in _dc_build_form(dc).items()}
        return templates.TemplateResponse(request, tmpl, _dc_edit_ctx(dc, form, str(exc)), status_code=400)
    dc.name = name
    dc.description = (raw.get("description") or "").strip()
    dc.content = content
    db.commit()
    _flash(request, f"Datacenter “{name}” updated.")
    return RedirectResponse(f"/datacenters/{dc.id}", status_code=303)


@router.post("/datacenters/{dc_id}/quick-edit")
async def dc_quick_edit(dc_id: int, request: Request, db: Session = Depends(get_db)):
    """Inline single-field edit from the detail page (JSON {field, value}): rename, or set/change/clear
    the credentials. Keeps the auth block coherent — preserves provider-specific identity (OpenStack
    project, Proxmox token-id) and seeds defaults when a password is first set on an open lab."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    dc = _owned(db, dc_id, user)
    try:
        data = await request.json()
    except Exception:
        data = {}
    field = (data.get("field") or "").strip()
    value = (data.get("value") or "").strip()

    if field == "name":
        if not value:
            return JSONResponse({"error": "Name can’t be empty."}, status_code=400)
        dc.name = value
        db.commit()
        return JSONResponse({"ok": True, "value": dc.name})

    if dc.provider not in _DC_IDENTITY:
        return JSONResponse({"error": "This datacenter type has no editable credentials."}, status_code=400)
    secret_key = "secret" if dc.provider == "proxmox" else "password"
    id_key = "token_id" if dc.provider == "proxmox" else "username"
    content = dict(dc.content or {})
    auth = dict(content.get("auth") or {})

    if field == "password":
        _quick_set_secret(content, dc.provider, value, secret_key)
        dc.content = content
        db.commit()
        return JSONResponse({"ok": True, "configured": dc_creds.configured(content.get("auth") or {}, secret_key)})

    if field in ("username", "token_id"):
        if not dc_creds.configured(auth, secret_key):
            return JSONResponse({"error": "Set a password first to enable authentication."}, status_code=400)
        auth[id_key] = value or _DC_IDENTITY[dc.provider][id_key]
        content["auth"] = auth
        dc.content = content
        db.commit()
        return JSONResponse({"ok": True, "value": auth[id_key]})

    return JSONResponse({"error": "Unknown field."}, status_code=400)


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
