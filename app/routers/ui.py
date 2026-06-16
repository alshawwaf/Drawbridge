"""Server-rendered portal UI (Jinja2 + HTMX)."""
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..links import public_url
from ..models import Feed, FeedPoll, FeedType, User
from ..security import get_user_or_none, new_feed_token, verify_password
from ..services.render import (
    normalize_generic_dc_content,
    normalize_network_feed_flat,
    normalize_network_feed_json,
    render_feed,
)

router = APIRouter(include_in_schema=False)
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# How many recent polls the feed page shows inline; the full history lives in the Activity log.
POLL_PREVIEW = 6

# --- Generic Data Center default (the canonical sk167210 sample) -----------------------
DEFAULT_FEED_NAME = "Generic-DC-Example"
DEFAULT_FEED_DESCRIPTION = "Generic Data Center file example"
DEFAULT_OBJECTS_TEXT = (
    "Object A name = 91.198.174.192, 20.0.0.0/24, 10.1.1.2-10.1.1.10 | Example for IPv4 addresses\n"
    "Object B name = 2001:0db8:85a3:0000:0000:8a2e:0370:7334, "
    "0064:ff9b:0000:0000:0000:0000:1234:5678/96, "
    "2001:0db8:85a3:0000:0000:8a2e:2020:0-2001:0db8:85a3:0000:0000:8a2e:2020:5 | Example for IPv6 addresses"
)

# --- Network Feed default (a small mixed blocklist) ------------------------------------
DEFAULT_NETFEED_NAME = "Network-Feed-Example"
DEFAULT_NETFEED_DESCRIPTION = "Demo blocklist"
# Per-data-type example entries; the form swaps to the matching set when data type changes,
# so the prefilled sample always validates under the selected type.
NETFEED_EXAMPLES = {
    "ip": "198.51.100.0/24\n203.0.113.10\n203.0.113.20-203.0.113.40",
    "domain": "*.malicious-example.com\nphishing-example.net\nbad.example.org",
    "ip_domain": (
        "198.51.100.0/24\n203.0.113.10\n203.0.113.20-203.0.113.40\n"
        "*.malicious-example.com\nphishing-example.net"
    ),
}
DEFAULT_NETFEED_ENTRIES = NETFEED_EXAMPLES["ip_domain"]
# JSON mode is free-form: the SE authors any JSON and supplies the JQ query to extract values.
DEFAULT_NETFEED_JSON_BODY = (
    "{\n"
    '  "version": "1.0",\n'
    '  "blocklist": [\n'
    '    { "value": "*.malicious-example.com" },\n'
    '    { "value": "phishing-example.net" },\n'
    '    { "value": "bad.example.org" }\n'
    "  ]\n"
    "}"
)
DEFAULT_JQ_QUERY = ".blocklist[].value"


def _default_form() -> dict:
    return {
        "name": DEFAULT_FEED_NAME,
        "description": DEFAULT_FEED_DESCRIPTION,
        "interval_seconds": get_settings().default_gdc_interval,
        "auth_header_key": "",
        "objects_text": DEFAULT_OBJECTS_TEXT,
    }


def _default_network_form() -> dict:
    return {
        "name": DEFAULT_NETFEED_NAME,
        "description": DEFAULT_NETFEED_DESCRIPTION,
        "data_type": "ip_domain",
        "feed_format": "flat",
        "entries_text": DEFAULT_NETFEED_ENTRIES,
        "json_body": DEFAULT_NETFEED_JSON_BODY,
        "jq_query": DEFAULT_JQ_QUERY,
        "interval_seconds": 3600,
        "basic_user": "",
    }


def parse_objects_text(text: str) -> list[dict]:
    """Generic DC quick-entry: one object per line, 'Name = range1, range2 | optional description'."""
    objects: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        description = ""
        if "|" in line:
            line, description = (part.strip() for part in line.split("|", 1))
        if "=" not in line:
            raise ValueError(f"Line must be 'Name = range1, range2': {raw.strip()!r}")
        name, rhs = line.split("=", 1)
        ranges = [r.strip() for r in rhs.split(",") if r.strip()]
        if not name.strip() or not ranges:
            raise ValueError(f"Line needs a name and at least one range: {raw.strip()!r}")
        objects.append({"name": name.strip(), "description": description, "ranges": ranges})
    if not objects:
        raise ValueError("Enter at least one object.")
    return objects


def parse_entries_text(text: str) -> list[str]:
    """Network Feed quick-entry: one entry per line; '#' lines and blanks are ignored."""
    entries = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not entries:
        raise ValueError("Enter at least one entry.")
    return entries


def _item_count(feed: Feed) -> int:
    if feed.type == FeedType.network_feed:
        return len(feed.content.get("entries", []))
    return len(feed.content.get("objects", []))


_DT_LABELS = {"ip": "IP", "domain": "Domain", "ip_domain": "IP/Domain"}


def _count_label(feed: Feed) -> str:
    # JSON feeds have a custom structure we don't parse, so item count is N/A.
    if feed.type == FeedType.network_feed and feed.content.get("format") == "json":
        return "—"
    return str(_item_count(feed))


def _selections_label(feed: Feed) -> str:
    """Short description of a feed's format/data-type selections (shown + filterable in the table)."""
    if feed.type != FeedType.network_feed:
        return ""
    fmt = "JSON" if feed.content.get("format") == "json" else "Flat list"
    return f"{fmt} · {_DT_LABELS.get(feed.content.get('data_type', ''), '')}"


def _flash(request: Request, text: str, kind: str = "success") -> None:
    request.session["flash"] = {"text": text, "type": kind}


def _pop_flash(request: Request) -> dict | None:
    return request.session.pop("flash", None)


def _owned(db: Session, feed_id: int, user: User) -> Feed:
    feed = db.get(Feed, feed_id)
    if feed is None or feed.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed


# --- Auth ------------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.username == username))
    if user is None or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid credentials"}, status_code=401
        )
    request.session["uid"] = user.id
    return RedirectResponse("/", status_code=303)


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# --- Dashboard -------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feeds = db.scalars(
        select(Feed).where(Feed.owner_id == user.id).order_by(Feed.created_at.desc())
    ).all()
    rows = [{
        "feed": f, "url": public_url(f),
        "count": _count_label(f), "selections": _selections_label(f),
    } for f in feeds]
    type_counts: dict[str, int] = {}
    for f in feeds:
        type_counts[f.type.value] = type_counts.get(f.type.value, 0) + 1
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"user": user, "rows": rows, "type_counts": type_counts, "flash": _pop_flash(request)},
    )


# --- New feed: chooser then per-type forms ---------------------------------------------
@router.get("/feeds/new")
def new_feed_redirect(request: Request, db: Session = Depends(get_db)):
    # The feed-type picker is a dropdown menu now; send direct hits to the Generic DC form.
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/feeds/new/generic-dc", status_code=303)


@router.get("/feeds/new/generic-dc", response_class=HTMLResponse)
def new_generic_page(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request, "feed_new_generic.html", {"error": None, "form": _default_form()}
    )


@router.post("/feeds/new/generic-dc")
def create_generic(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    interval_seconds: int = Form(10),
    auth_header_key: str = Form(""),
    auth_header_value: str = Form(""),
    objects_text: str = Form(""),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        content = normalize_generic_dc_content(parse_objects_text(objects_text), description)
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "feed_new_generic.html",
            {"error": str(exc), "form": {
                "name": name, "description": description, "interval_seconds": interval_seconds,
                "auth_header_key": auth_header_key, "objects_text": objects_text,
            }},
            status_code=400,
        )
    feed = Feed(
        token=new_feed_token(),
        type=FeedType.generic_dc,
        name=name,
        description=description,
        content=content,
        interval_seconds=interval_seconds,
        auth_header_key=auth_header_key or None,
        auth_header_value=auth_header_value or None,
        owner_id=user.id,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    _flash(request, f"Generic Data Center feed “{name}” created.")
    return RedirectResponse(f"/feeds/{feed.id}", status_code=303)


@router.get("/feeds/new/network-feed", response_class=HTMLResponse)
def new_network_page(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "feed_new_network.html",
        {"error": None, "form": _default_network_form(), "examples": NETFEED_EXAMPLES},
    )


@router.post("/feeds/new/network-feed")
def create_network(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    data_type: str = Form("ip_domain"),
    feed_format: str = Form("flat"),
    entries_text: str = Form(""),
    json_body: str = Form(""),
    jq_query: str = Form(""),
    interval_seconds: int = Form(3600),
    basic_user: str = Form(""),
    basic_pass: str = Form(""),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        if feed_format == "json":
            content = normalize_network_feed_json(json_body, jq_query, data_type)
        else:
            content = normalize_network_feed_flat(parse_entries_text(entries_text), data_type)
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "feed_new_network.html",
            {"error": str(exc), "examples": NETFEED_EXAMPLES, "form": {
                "name": name, "description": description, "data_type": data_type,
                "feed_format": feed_format, "entries_text": entries_text,
                "json_body": json_body, "jq_query": jq_query,
                "interval_seconds": interval_seconds, "basic_user": basic_user,
            }},
            status_code=400,
        )
    feed = Feed(
        token=new_feed_token(),
        type=FeedType.network_feed,
        name=name,
        description=description,
        content=content,
        interval_seconds=interval_seconds,
        auth_header_key=basic_user or None,
        auth_header_value=basic_pass or None,
        owner_id=user.id,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    _flash(request, f"Network Feed “{name}” created.")
    return RedirectResponse(f"/feeds/{feed.id}", status_code=303)


# --- Feed detail / polls / delete ------------------------------------------------------
@router.get("/feeds/{feed_id}", response_class=HTMLResponse)
def feed_detail(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feed = _owned(db, feed_id, user)
    body, _ = render_feed(feed)
    return templates.TemplateResponse(
        request,
        "feed_detail.html",
        {"feed": feed, "url": public_url(feed), "preview": body, "flash": _pop_flash(request)},
    )


@router.get("/feeds/{feed_id}/polls-fragment", response_class=HTMLResponse)
def polls_fragment(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return HTMLResponse("", status_code=401)
    feed = _owned(db, feed_id, user)
    # Count + latest few via SQL (don't load the whole — possibly huge — poll history).
    total = db.scalar(
        select(func.count()).select_from(FeedPoll).where(FeedPoll.feed_id == feed.id)
    ) or 0
    recent = db.scalars(
        select(FeedPoll)
        .where(FeedPoll.feed_id == feed.id)
        .order_by(FeedPoll.at.desc())
        .limit(POLL_PREVIEW)
    ).all()
    return templates.TemplateResponse(
        request,
        "_polls.html",
        {"polls": recent, "total": total, "last": recent[0] if recent else None},
    )


@router.post("/feeds/{feed_id}/delete")
def delete_feed_form(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feed = _owned(db, feed_id, user)
    name = feed.name
    db.delete(feed)
    db.commit()
    _flash(request, f"Feed “{name}” deleted.")
    return RedirectResponse("/", status_code=303)
