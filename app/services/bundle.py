"""Portable PoV bundle: export the SE's simulated environment (feeds, datacenters, gateways,
dynamic layers) to a JSON file a colleague can import, and import one back.

Bundles never carry credentials (org policy: no secrets in unencrypted files, and encrypted
ciphertext wouldn't decrypt under another instance's key anyway). On export we drop feed auth, the
datacenter ``content.auth`` block, and the gateway password; on import those come up credential-less
and the SE re-enters them. Tokens (public feed/DC URLs) are regenerated on import, and a layer's
gateway reference is remapped by bundle index so it re-links to the imported gateway.
"""
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Datacenter, DynamicLayer, Feed, FeedType, Gateway, User
from ..security import new_feed_token

BUNDLE_VERSION = 1


def _strip_dc_auth(content: dict) -> dict:
    """Drop the whole auth block (identity + secret) so an imported datacenter comes up open."""
    c = dict(content or {})
    c.pop("auth", None)
    return c


def _export_layer(layer: DynamicLayer, gw_index: dict[int, int]) -> dict:
    content = dict(layer.content or {})
    gid = content.pop("gateway_id", None)  # numeric id is instance-specific — replace with a bundle ref
    if gid in gw_index:
        content["gateway_ref"] = gw_index[gid]
    return {"name": layer.name, "description": layer.description or "",
            "layer_name": layer.layer_name or "dynamic_layer", "content": content}


def export_bundle(db: Session, user: User) -> dict:
    """Serialize the user's whole simulated environment to a portable, secret-free dict."""
    feeds = db.scalars(select(Feed).where(Feed.owner_id == user.id).order_by(Feed.id)).all()
    dcs = db.scalars(select(Datacenter).where(Datacenter.owner_id == user.id).order_by(Datacenter.id)).all()
    gws = db.scalars(select(Gateway).where(Gateway.owner_id == user.id).order_by(Gateway.id)).all()
    layers = db.scalars(select(DynamicLayer).where(DynamicLayer.owner_id == user.id).order_by(DynamicLayer.id)).all()
    gw_index = {g.id: i for i, g in enumerate(gws)}  # real gateway id → position in the exported list
    return {
        "dcsim_bundle": BUNDLE_VERSION,
        "feeds": [{"type": f.type.value, "name": f.name, "description": f.description or "",
                   "content": f.content or {}, "interval_seconds": f.interval_seconds} for f in feeds],
        "datacenters": [{"provider": d.provider, "name": d.name, "description": d.description or "",
                         "content": _strip_dc_auth(d.content)} for d in dcs],
        "gateways": [{"name": g.name, "host": g.host, "port": g.port, "username": g.username,
                      "cert_pem": g.cert_pem or "", "auto_trust": bool(g.auto_trust)} for g in gws],
        "dynamic_layers": [_export_layer(layer, gw_index) for layer in layers],
    }


def import_bundle(db: Session, user: User, data: dict) -> dict:
    """Create entities from a bundle under ``user`` (additive — never deletes existing). Returns
    per-type counts plus a list of skipped items. Raises ValueError if it isn't a bundle."""
    if not isinstance(data, dict) or int(data.get("dcsim_bundle") or 0) < 1:
        raise ValueError("This file isn't a DC Simulator bundle.")
    counts = {"feeds": 0, "datacenters": 0, "gateways": 0, "dynamic_layers": 0}
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

    gw_objs: list[Gateway] = []
    for g in data.get("gateways") or []:
        gw = Gateway(token=new_feed_token(), name=g.get("name") or "Imported gateway",
                     host=g.get("host") or "", port=int(g.get("port") or 443),
                     username=g.get("username") or "", cert_pem=g.get("cert_pem") or "",
                     auto_trust=bool(g.get("auto_trust", True)), owner_id=user.id)
        db.add(gw)
        gw_objs.append(gw)
        counts["gateways"] += 1
    db.flush()  # assign gateway ids so layer references can be remapped

    for layer in data.get("dynamic_layers") or []:
        content = dict(layer.get("content") or {})
        ref = content.pop("gateway_ref", None)
        if isinstance(ref, int) and 0 <= ref < len(gw_objs):
            content["gateway_id"] = gw_objs[ref].id  # re-link to the imported gateway
        db.add(DynamicLayer(token=new_feed_token(), name=layer.get("name") or "Imported layer",
                            description=layer.get("description") or "",
                            layer_name=layer.get("layer_name") or "dynamic_layer",
                            content=content, owner_id=user.id))
        counts["dynamic_layers"] += 1

    db.commit()
    return {"counts": counts, "skipped": skipped}


def seed_bundle() -> dict:
    """A realistic, ready-to-demo environment (feeds + datacenters + a gateway + a linked dynamic
    layer) imported by the one-click 'Seed demo environment' button. Same format as an export."""
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
        "gateways": [
            {"name": "Demo-Gateway", "host": "10.1.1.1", "port": 443, "username": "admin",
             "cert_pem": "", "auto_trust": True},
        ],
        "dynamic_layers": [
            {"name": "Demo-Dynamic-Layer", "layer_name": "dynamic_layer", "description": "Sample updatable policy",
             "content": {
                 "operation": "replace", "comments": "Seeded demo layer", "tags": ["demo"],
                 "gateway_ref": 0,
                 "objects": {"hosts": [{"name": "web-server-1", "ipv4-address": "10.10.0.11"}]},
                 "referenced_objects": {},
                 "rulebase": [
                     {"name": "Allow web to app", "action": "Accept"},
                     {"name": "Block known-bad", "action": "Drop"}]}},
        ],
    }
