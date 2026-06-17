"""Mock OpenStack API (Keystone v3 + Nova + Neutron) that Check Point's CloudGuard Controller
connects to. Configure the SmartConsole OpenStack object's Hostname to
``<portal>/openstack/<token>/v3`` with any username/password; the catalog returned by Keystone
points CP at this portal's Nova/Neutron, which serve the datacenter's simulated inventory.
"""
from fastapi import APIRouter, Depends, Header, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..models import Datacenter
from ..services import openstack as os_mock

router = APIRouter(tags=["openstack-mock"])


def _dc(db: Session, token: str) -> Datacenter:
    dc = db.scalar(select(Datacenter).where(Datacenter.token == token, Datacenter.provider == "openstack"))
    if dc is None:
        raise HTTPException(status_code=404, detail="OpenStack datacenter not found")
    return dc


def _require_token(x_auth_token: str | None) -> None:
    if not x_auth_token:
        raise HTTPException(status_code=401, detail="Missing X-Auth-Token")


@router.get("/openstack/{token}/v3")
def keystone_version(token: str, db: Session = Depends(get_db)):
    _dc(db, token)
    base = get_settings().base_url.rstrip("/")
    return {"version": {"id": "v3.14", "status": "stable",
                        "links": [{"rel": "self", "href": f"{base}/openstack/{token}/v3/"}]}}


@router.post("/openstack/{token}/v3/auth/tokens")
def keystone_auth(token: str, body: dict, db: Session = Depends(get_db)):
    dc = _dc(db, token)
    auth = (body or {}).get("auth", {}) or {}
    creds = ((auth.get("identity") or {}).get("password") or {}).get("user") or {}
    user = creds.get("name", "admin")
    password = creds.get("password", "")
    if not os_mock.auth_ok(dc, user, password):  # wrong creds -> realistic Keystone 401
        return JSONResponse(os_mock.keystone_error_401(), status_code=401)
    project = os_mock.configured_project(dc)
    subject, resp = os_mock.keystone_token(dc, get_settings().base_url, user=user, project=project)
    return JSONResponse(resp, status_code=201, headers={"X-Subject-Token": subject})


@router.get("/openstack/{token}/v3/auth/projects")
def keystone_projects(token: str, db: Session = Depends(get_db),
                      x_auth_token: str | None = Header(default=None)):
    """Projects the token can access — CloudGuard enumerates these after authenticating."""
    _require_token(x_auth_token)
    dc = _dc(db, token)
    return os_mock.keystone_projects(dc, get_settings().base_url, project=os_mock.configured_project(dc))


@router.get("/openstack/{token}/nova/v2.1/servers/detail")
@router.get("/openstack/{token}/nova/v2.1/servers")
def nova_servers(token: str, db: Session = Depends(get_db), x_auth_token: str | None = Header(default=None)):
    _require_token(x_auth_token)
    return os_mock.nova_servers(_dc(db, token))


@router.get("/openstack/{token}/neutron/v2.0/subnets")
def neutron_subnets(token: str, db: Session = Depends(get_db), x_auth_token: str | None = Header(default=None)):
    _require_token(x_auth_token)
    return os_mock.neutron_subnets(_dc(db, token))


@router.get("/openstack/{token}/neutron/v2.0/security-groups")
def neutron_security_groups(token: str, db: Session = Depends(get_db), x_auth_token: str | None = Header(default=None)):
    _require_token(x_auth_token)
    return os_mock.neutron_security_groups(_dc(db, token))


@router.get("/openstack/{token}/neutron/v2.0/networks")
def neutron_networks(token: str, db: Session = Depends(get_db), x_auth_token: str | None = Header(default=None)):
    _require_token(x_auth_token)
    return os_mock.neutron_networks(_dc(db, token))


@router.get("/openstack/{token}/neutron/v2.0/ports")
def neutron_ports(token: str, db: Session = Depends(get_db), x_auth_token: str | None = Header(default=None)):
    _require_token(x_auth_token)
    return os_mock.neutron_ports(_dc(db, token))
