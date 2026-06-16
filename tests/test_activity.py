"""Activity-log redaction, scoped clearing, and paginated rendering."""
import datetime as dt

from sqlalchemy import create_engine, delete, select
from sqlalchemy.orm import sessionmaker

from app import models  # noqa: F401  (register tables on the metadata)
from app.db import Base
from app.models import ActivityLog
from app.routers.activity import KIND_LABELS
from app.routers.ui import templates
from app.services.activity import redact_body, redact_headers


def _render(name, **ctx):
    ctx.setdefault("request", None)
    return templates.env.get_template(name).render(**ctx)


def _row(kind="feed_poll"):
    return type("R", (), {"at": dt.datetime(2026, 6, 16, 23, 24, 45), "kind": kind, "method": "GET",
                          "path": "/gdc/x.json", "source_ip": "1.2.3.4", "status": 200,
                          "duration_ms": 9, "detail": {}})()


def test_redact_headers_masks_secrets():
    out = redact_headers({"Authorization": "Basic abc", "X-chkp-sid": "sid123",
                          "Cookie": "session=x", "Content-Type": "application/json"})
    assert out["Authorization"] == "(masked)"
    assert out["X-chkp-sid"] == "(masked)"
    assert out["Cookie"] == "(masked)"
    assert out["Content-Type"] == "application/json"


def test_redact_body_redacts_sensitive_keys_recursively():
    out = redact_body({"user": "admin", "password": "secret",
                       "nested": {"token": "t", "ip-address": "1.1.1.1"}})
    assert out["password"] == "***"
    assert out["nested"]["token"] == "***"
    assert out["user"] == "admin"
    assert out["nested"]["ip-address"] == "1.1.1.1"


def test_redact_body_handles_lists():
    out = redact_body([{"password": "p"}, {"name": "ok"}])
    assert out[0]["password"] == "***"
    assert out[1]["name"] == "ok"


def test_clear_button_is_scoped_to_the_selected_kind():
    counts = {"all": 4397, "feed_poll": 4029, "layer_apply": 19}
    all_html = _render("activity.html", kind="all", counts=counts, kind_labels=KIND_LABELS, flash=None)
    assert ">Clear log<" in all_html and 'name="kind" value="all"' in all_html
    fp_html = _render("activity.html", kind="feed_poll", counts=counts, kind_labels=KIND_LABELS, flash=None)
    assert "Clear Feed poll (4029)" in fp_html and 'name="kind" value="feed_poll"' in fp_html


def test_pager_renders_numbered_windowed_pages():
    html = _render("_activity_rows.html", rows=[_row()], kind="all", page=6, pages=88,
                   total=4399, kind_labels=KIND_LABELS)
    assert "Page 6 of 88" in html
    assert "« First" in html and "Last »" in html
    assert 'data-page="1"' in html and 'data-page="88"' in html      # First + Last
    assert 'data-page="5"' in html and 'data-page="7"' in html       # window around page 6
    assert 'aria-current="page"' in html                             # the current page is marked


def test_clear_by_kind_deletes_only_that_category():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    db.add_all([ActivityLog(kind="feed_poll", path="/a"), ActivityLog(kind="feed_poll", path="/b"),
                ActivityLog(kind="layer_apply", path="/c")])
    db.commit()
    db.execute(delete(ActivityLog).where(ActivityLog.kind == "feed_poll"))
    db.commit()
    remaining = db.scalars(select(ActivityLog)).all()
    assert len(remaining) == 1 and remaining[0].kind == "layer_apply"
