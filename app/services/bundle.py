"""Portable PoV bundle: export the SE's simulated environment (feeds + datacenters) to a JSON file a
colleague can import, and import one back.

Bundles never carry credentials (org policy: no secrets in unencrypted files, and encrypted
ciphertext wouldn't decrypt under another instance's key anyway). On export we drop feed auth and the
datacenter ``content.auth`` block; on import those come up credential-less and the SE re-enters them.
Tokens (public feed/DC URLs) are regenerated on import.
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Datacenter, Feed, FeedType, User
from ..security import new_feed_token

BUNDLE_VERSION = 1


def _strip_dc_auth(content: dict) -> dict:
    """Drop the whole auth block (identity + secret) so an imported datacenter comes up open."""
    c = dict(content or {})
    c.pop("auth", None)
    return c


def export_bundle(db: Session, user: User) -> dict:
    """Serialize the user's whole simulated environment to a portable, secret-free dict."""
    feeds = db.scalars(select(Feed).where(Feed.owner_id == user.id).order_by(Feed.id)).all()
    dcs = db.scalars(select(Datacenter).where(Datacenter.owner_id == user.id).order_by(Datacenter.id)).all()
    return {
        "dcsim_bundle": BUNDLE_VERSION,
        "feeds": [{"type": f.type.value, "name": f.name, "description": f.description or "",
                   "content": f.content or {}, "interval_seconds": f.interval_seconds} for f in feeds],
        "datacenters": [{"provider": d.provider, "name": d.name, "description": d.description or "",
                         "content": _strip_dc_auth(d.content)} for d in dcs],
    }


def import_bundle(db: Session, user: User, data: dict) -> dict:
    """Create entities from a bundle under ``user`` (additive — never deletes existing). Returns
    per-type counts plus a list of skipped items. Raises ValueError if it isn't a bundle."""
    if not isinstance(data, dict) or int(data.get("dcsim_bundle") or 0) < 1:
        raise ValueError("This file isn't a DC Simulator bundle.")
    counts = {"feeds": 0, "datacenters": 0}
    skipped: list[str] = []

    for f in data.get("feeds") or []:
        try:
            ftype = FeedType(f.get("type"))
        except (ValueError, KeyError):
            skipped.append(f"feed “{f.get('name', '?')}” (unknown type {f.get('type')!r})")
            continue
        db.add(Feed(token=new_feed_token(), type=ftype, name=f.get("name") or "Imported feed",
                    description=f.get("description") or "", content=f.get("content") or {},
                    interval_seconds=int(f.get("interval_seconds") or 10), owner_id=user.id))
        counts["feeds"] += 1

    for d in data.get("datacenters") or []:
        db.add(Datacenter(token=new_feed_token(), provider=d.get("provider") or "openstack",
                          name=d.get("name") or "Imported datacenter", description=d.get("description") or "",
                          content=_strip_dc_auth(d.get("content")), owner_id=user.id))
        counts["datacenters"] += 1

    db.commit()
    return {"counts": counts, "skipped": skipped}


def seed_bundle() -> dict:
    """A realistic, ready-to-demo environment (feeds + datacenters) imported by the one-click
    'Seed demo environment' button. Same format as an export."""
    return {
        "dcsim_bundle": BUNDLE_VERSION,
        "feeds": [
            {"type": "generic_dc", "name": "Demo-Datacenter-Objects", "interval_seconds": 60,
             "description": "Generic Data Center objects for SmartConsole import",
             "content": {"objects": [
                 {"name": "Prod-Web-Servers", "id": "11111111-1111-1111-1111-111111111111",
                  "description": "Production web tier", "ranges": ["10.10.0.0/24", "203.0.113.10"]},
                 {"name": "Partner-Networks", "id": "22222222-2222-2222-2222-222222222222",
                  "description": "", "ranges": ["198.51.100.0/24"]}]}},
            {"type": "network_feed", "name": "Demo-Threat-Blocklist", "interval_seconds": 3600,
             "description": "Flat IP blocklist", "content": {
                 "format": "flat", "data_type": "ip",
                 "entries": ["203.0.113.66", "198.51.100.0/24", "192.0.2.55"]}},
            {"type": "ioc", "name": "Demo-IoC-Feed", "interval_seconds": 3600,
             "description": "Custom Intelligence indicators", "content": {
                 "format": "cp_csv", "indicators": [
                     {"name": "ioc-1", "value": "203.0.113.66", "type": "IP", "confidence": "high",
                      "severity": "high", "product": "AB", "comment": "C2 beacon"},
                     {"name": "ioc-2", "value": "evil.example.com", "type": "Domain", "confidence": "medium",
                      "severity": "medium", "product": "AB", "comment": "phishing host"}]}},
        ],
        "datacenters": [
            {"provider": "nutanix", "name": "Nutanix-Demo", "description": "Mock Nutanix Prism", "content": {
                "vms": [
                    {"name": "web-vm-1", "ip": "10.50.0.11", "categories": {"Environment": "Production", "AppType": "Web"}},
                    {"name": "web-vm-2", "ip": "10.50.0.12", "categories": {"Environment": "Production", "AppType": "Web"}},
                    {"name": "db-vm-1", "ip": "10.50.0.21", "categories": {"Environment": "Production", "AppType": "Database"}}]}},
            {"provider": "openstack", "name": "OpenStack-Demo", "description": "Mock OpenStack", "content": {
                "instances": [
                    {"name": "web-1", "ip": "10.0.0.11", "tags": ["web-sg", "prod-sg"]},
                    {"name": "db-1", "ip": "10.0.0.21", "tags": ["db-sg", "prod-sg"]}],
                "subnets": [{"name": "app-subnet", "cidr": "10.0.0.0/24"}],
                "security_groups": [{"name": "web-sg"}, {"name": "db-sg"}, {"name": "prod-sg"}]}},
        ],
    }


def sbt_lab_bundle() -> dict:
    """The **SBT Lab Environment** preset — mock datacenters + feeds that MIRROR the instructor's real
    lab topology (segments 10.1.1/2/3.0/24 + the external contractor net 203.0.113.0/24). The mock
    vCenter / NSX-T advertise the VMs at their **real lab IPs on purpose**, so a trainee can connect
    CloudGuard, import a VM, drop it into a rule, and verify with a *real* ping through the live gateway."""
    vcenter_vms = [   # vCenter tags are bare strings (imported as tag objects)
        {"name": "Windows-Client", "ip": "10.1.1.222", "tags": ["SBT", "client", "Windows", "seg-mgmt"],
         "power": "poweredOn", "guest_os": "windows9_64Guest"},
        {"name": "Windows-Server", "ip": "10.1.2.250", "tags": ["SBT", "server", "Windows", "seg-app"],
         "power": "poweredOn", "guest_os": "windows9Server64Guest"},
        {"name": "AI-Ubuntu", "ip": "10.1.3.33", "tags": ["SBT", "server", "Linux", "seg-dmz", "ai"],
         "power": "poweredOn", "guest_os": "ubuntu64Guest"},
        {"name": "Kali-Linux", "ip": "203.0.113.5", "tags": ["contractor", "untrusted", "Linux", "external"],
         "power": "poweredOn", "guest_os": "otherLinux64Guest"},
    ]
    nsxt_vms = [   # NSX-T tags are scope=value pairs; groups below match on a member tag
        {"name": "Windows-Client", "ip": "10.1.1.222", "tags": ["zone=sbt", "role=client", "os=windows"]},
        {"name": "Windows-Server", "ip": "10.1.2.250", "tags": ["zone=sbt", "role=server", "os=windows"]},
        {"name": "AI-Ubuntu", "ip": "10.1.3.33", "tags": ["zone=sbt", "role=server", "os=linux"]},
        {"name": "Kali-Linux", "ip": "203.0.113.5", "tags": ["zone=external", "role=contractor", "trust=untrusted"]},
    ]
    return {
        "dcsim_bundle": BUNDLE_VERSION,
        "feeds": [
            {"type": "generic_dc", "name": "SBT-Network-Segments", "interval_seconds": 60,
             "description": "SBT lab network segments as importable Data Center objects",
             "content": {"objects": [
                 {"name": "SBT-Mgmt-Net", "id": "aaaa0001-0000-0000-0000-000000000001",
                  "description": "Management / client segment", "ranges": ["10.1.1.0/24"]},
                 {"name": "SBT-App-Net", "id": "aaaa0001-0000-0000-0000-000000000002",
                  "description": "Server / application segment", "ranges": ["10.1.2.0/24"]},
                 {"name": "SBT-DMZ-Net", "id": "aaaa0001-0000-0000-0000-000000000003",
                  "description": "DMZ / AI workloads", "ranges": ["10.1.3.0/24"]},
                 {"name": "Contractor-Net", "id": "aaaa0001-0000-0000-0000-000000000004",
                  "description": "External PenTest contractor (ISP1)", "ranges": ["203.0.113.0/24"]}]}},
            {"type": "network_feed", "name": "SBT-Threat-Blocklist", "interval_seconds": 3600,
             "description": "IPs the lab gateway should block (incl. the contractor host)",
             "content": {"format": "flat", "data_type": "ip",
                         "entries": ["203.0.113.5", "198.51.100.0/24", "192.0.2.0/24"]}},
            {"type": "ioc", "name": "SBT-C2-Indicators", "interval_seconds": 3600,
             "description": "Threat indicators relevant to the SBT lab",
             "content": {"format": "cp_csv", "indicators": [
                 {"name": "contractor-host", "value": "203.0.113.5", "type": "IP", "confidence": "high",
                  "severity": "critical", "product": "AB", "comment": "PenTest contractor (Kali) — untrusted"},
                 {"name": "phishing-host", "value": "malicious.example.net", "type": "Domain",
                  "confidence": "medium", "severity": "high", "product": "AB", "comment": "phishing domain"}]}},
        ],
        "datacenters": [
            {"provider": "vcenter", "name": "SBT-vCenter",
             "description": "Mock vCenter mirroring the SBT lab VMs (real IPs)", "content": {"vms": vcenter_vms}},
            {"provider": "nsxt", "name": "SBT-NSX-T",
             "description": "Mock NSX-T: the SBT lab VMs + dynamic security groups", "content": {
                 "vms": nsxt_vms, "groups": [
                     {"name": "SBT-Servers", "member_tag": "role=server", "tags": ["env=sbt"]},
                     {"name": "Untrusted-Contractors", "member_tag": "trust=untrusted", "tags": []},
                     {"name": "SBT-Zone", "member_tag": "zone=sbt", "tags": []}]}},
        ],
    }
