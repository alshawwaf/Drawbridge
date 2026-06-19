"""PoV bundle export/import: round-trips the simulated environment, regenerates tokens, remaps a
layer's gateway reference, and never carries credentials (feed auth, DC content.auth, gateway secret)."""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import models  # noqa: F401  (register tables)
from app.db import Base
from app.models import Datacenter, DynamicLayer, Feed, FeedType, Gateway, User
from app.services import bundle


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False)()


def _user(db, name):
    u = User(username=name, password_hash="x")
    db.add(u)
    db.commit()
    return u


def _populate(db, user):
    db.add(Feed(token="t-feed", type=FeedType.generic_dc, name="F1", content={"objects": []},
                auth_header_key="X-Tok", auth_header_value="SECRET", interval_seconds=60, owner_id=user.id))
    db.add(Datacenter(token="t-dc", provider="nutanix", name="DC1",
                      content={"vms": [{"name": "v", "ip": "1.1.1.1", "categories": {}}],
                               "auth": {"username": "admin", "password_enc": "v1.SECRET"}}, owner_id=user.id))
    gw = Gateway(token="t-gw", name="GW1", host="10.0.0.1", port=443, username="admin", owner_id=user.id)
    db.add(gw)
    db.commit()
    db.add(DynamicLayer(token="t-layer", name="L1", layer_name="dynamic_layer",
                        content={"rulebase": [{"name": "r1", "action": "Drop"}], "gateway_id": gw.id},
                        owner_id=user.id))
    db.commit()
    return gw


def test_export_carries_no_credentials():
    db = _session()
    user = _user(db, "a")
    _populate(db, user)
    b = bundle.export_bundle(db, user)
    feed = b["feeds"][0]
    assert "auth_header_value" not in feed and "auth_header_key" not in feed   # feed secret + key dropped
    assert "auth" not in b["datacenters"][0]["content"]                        # DC auth block dropped
    gw = b["gateways"][0]
    assert not any(k in gw for k in ("password", "secret", "ciphertext"))       # no gateway secret
    assert gw["username"] == "admin"                                            # non-secret identity kept


def test_round_trip_recreates_under_new_user_with_fresh_tokens():
    src = _session()
    a = _user(src, "a")
    _populate(src, a)
    data = bundle.export_bundle(src, a)

    dst = _session()
    b_user = _user(dst, "b")
    result = bundle.import_bundle(dst, b_user, data)
    assert result["counts"] == {"feeds": 1, "datacenters": 1, "gateways": 1, "dynamic_layers": 1}

    feed = dst.query(Feed).filter_by(owner_id=b_user.id).one()
    assert feed.name == "F1" and feed.token != "t-feed"          # recreated with a fresh token
    assert feed.auth_header_value is None                        # imported credential-less


def test_gateway_reference_remaps_to_imported_gateway():
    src = _session()
    a = _user(src, "a")
    _populate(src, a)
    data = bundle.export_bundle(src, a)
    # In the bundle the layer references the gateway by bundle index, not the original numeric id.
    assert data["dynamic_layers"][0]["content"].get("gateway_ref") == 0
    assert "gateway_id" not in data["dynamic_layers"][0]["content"]

    dst = _session()
    b_user = _user(dst, "b")
    bundle.import_bundle(dst, b_user, data)
    gw = dst.query(Gateway).filter_by(owner_id=b_user.id).one()
    layer = dst.query(DynamicLayer).filter_by(owner_id=b_user.id).one()
    assert layer.content["gateway_id"] == gw.id                  # re-linked to the imported gateway
    assert "gateway_ref" not in layer.content


def test_import_rejects_non_bundle():
    db = _session()
    u = _user(db, "a")
    for bad in ({}, {"foo": 1}, [], "nope"):
        with pytest.raises(ValueError):
            bundle.import_bundle(db, u, bad)


def test_import_skips_unknown_feed_type():
    db = _session()
    u = _user(db, "a")
    res = bundle.import_bundle(db, u, {"dcsim_bundle": 1, "feeds": [
        {"type": "bogus", "name": "Bad", "content": {}},
        {"type": "ioc", "name": "Good", "content": {"format": "cp_csv", "indicators": []}}]})
    assert res["counts"]["feeds"] == 1 and res["skipped"]        # one imported, one skipped


def test_seed_bundle_imports_cleanly_and_links_layer():
    db = _session()
    u = _user(db, "a")
    res = bundle.import_bundle(db, u, bundle.seed_bundle())
    assert res["counts"] == {"feeds": 3, "datacenters": 2, "gateways": 1, "dynamic_layers": 1}
    gw = db.query(Gateway).filter_by(owner_id=u.id).one()
    layer = db.query(DynamicLayer).filter_by(owner_id=u.id).one()
    assert layer.content["gateway_id"] == gw.id                  # seeded layer linked to the seeded gateway
