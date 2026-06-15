"""Server-rendered portal UI (Jinja2 + HTMX)."""
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..links import public_url
from ..models import Feed, FeedType, User
from ..security import get_user_or_none, new_feed_token, verify_password
from ..services.render import normalize_generic_dc_content, render_feed

router = APIRouter(include_in_schema=False)
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Default example shown in the new-feed form — the canonical sk167210 sample
# (one IPv4 object, one IPv6 object) so the form is one-click submittable.
DEFAULT_FEED_NAME = "Generic-DC-Example"
DEFAULT_FEED_DESCRIPTION = "Generic Data Center file example"
DEFAULT_OBJECTS_TEXT = (
    "Object A name = 91.198.174.192, 20.0.0.0/24, 10.1.1.2-10.1.1.10 | Example for IPv4 addresses\n"
    "Object B name = 2001:0db8:85a3:0000:0000:8a2e:0370:7334, "
    "0064:ff9b:0000:0000:0000:0000:1234:5678/96, "
    "2001:0db8:85a3:0000:0000:8a2e:2020:0-2001:0db8:85a3:0000:0000:8a2e:2020:5 | Example for IPv6 addresses"
)


def _default_form() -> dict:
    return {
        "name": DEFAULT_FEED_NAME,
        "description": DEFAULT_FEED_DESCRIPTION,
        "interval_seconds": get_settings().default_gdc_interval,
        "auth_header_key": "",
        "objects_text": DEFAULT_OBJECTS_TEXT,
    }


def parse_objects_text(text: str) -> list[dict]:
    """Parse the quick-entry textarea: one object per line,
    'Name = range1, range2' with an optional '| description' suffix."""
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


def _require_user(request: Request, db: Session) -> User:
    user = get_user_or_none(request, db)
    if user is None:
        raise HTTPException(status_code=307, headers={"Location": "/login"})
    return user


def _owned(db: Session, feed_id: int, user: User) -> Feed:
    feed = db.get(Feed, feed_id)
    if feed is None or feed.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed


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


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feeds = db.scalars(
        select(Feed).where(Feed.owner_id == user.id).order_by(Feed.created_at.desc())
    ).all()
    rows = [{"feed": f, "url": public_url(f), "count": len(f.content.get("objects", []))} for f in feeds]
    return templates.TemplateResponse(request, "dashboard.html", {"user": user, "rows": rows})


@router.get("/feeds/new", response_class=HTMLResponse)
def new_feed_page(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request, "feed_new.html", {"error": None, "form": _default_form()}
    )


@router.post("/feeds/new")
def create_feed_form(
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
        objects = parse_objects_text(objects_text)
        content = normalize_generic_dc_content(objects, description)
    except Exception as exc:  # ValidationError or ValueError → re-render with the message
        return templates.TemplateResponse(
            request,
            "feed_new.html",
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
    return RedirectResponse(f"/feeds/{feed.id}", status_code=303)


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
        {"feed": feed, "url": public_url(feed), "preview": body},
    )


@router.get("/feeds/{feed_id}/polls-fragment", response_class=HTMLResponse)
def polls_fragment(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return HTMLResponse("", status_code=401)
    feed = _owned(db, feed_id, user)
    return templates.TemplateResponse(request, "_polls.html", {"polls": feed.polls[:25]})


@router.post("/feeds/{feed_id}/delete")
def delete_feed_form(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feed = _owned(db, feed_id, user)
    db.delete(feed)
    db.commit()
    return RedirectResponse("/", status_code=303)
