"""Authenticated JSON API for managing simulated feeds."""
from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..links import public_url
from ..models import Feed, FeedType, User
from ..security import current_user, new_feed_token
from ..services.render import (
    normalize_generic_dc_content,
    normalize_ioc_content,
    normalize_network_feed_flat,
    normalize_network_feed_json,
    normalize_snort_content,
    render_feed,
)

router = APIRouter(prefix="/api", tags=["feeds"])


class FeedCreate(BaseModel):
    type: FeedType = FeedType.generic_dc
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    interval_seconds: int = Field(default=10, ge=1)
    auth_header_key: str | None = None
    auth_header_value: str | None = None
    # generic_dc
    objects: list[dict] = Field(default_factory=list)
    # network_feed (flat list)
    entries: list[str] = Field(default_factory=list)
    feed_format: str = "flat"
    data_type: str = "ip_domain"
    # network_feed (custom JSON)
    json_body: str = ""
    jq_query: str = ""
    # ioc
    indicators: list[dict] = Field(default_factory=list)
    ioc_format: str = "cp_csv"
    snort_rules: str = ""
    ioc_delimiter: str = ","
    ioc_comment: str = "#"


class FeedUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    auth_header_key: str | None = None
    auth_header_value: str | None = None
    objects: list[dict] | None = None
    entries: list[str] | None = None
    json_body: str | None = None
    jq_query: str | None = None
    indicators: list[dict] | None = None
    ioc_format: str | None = None
    snort_rules: str | None = None
    ioc_delimiter: str | None = None
    ioc_comment: str | None = None


def _build_content(
    ftype: FeedType,
    *,
    objects: list[dict] | None = None,
    entries: list[str] | None = None,
    feed_format: str = "flat",
    data_type: str = "ip_domain",
    json_body: str = "",
    jq_query: str = "",
    indicators: list[dict] | None = None,
    ioc_format: str = "cp_csv",
    snort_rules: str = "",
    ioc_delimiter: str = ",",
    ioc_comment: str = "#",
    description: str = "",
) -> dict:
    try:
        if ftype == FeedType.generic_dc:
            return normalize_generic_dc_content(objects or [], description)
        if ftype == FeedType.ioc:
            if ioc_format == "snort":
                return normalize_snort_content(snort_rules)
            return normalize_ioc_content(indicators or [], description, ioc_format,
                                         ioc_delimiter, ioc_comment)
        if ftype == FeedType.network_feed:
            if feed_format == "json":
                return normalize_network_feed_json(json_body, jq_query, data_type)
            return normalize_network_feed_flat(entries or [], data_type)
    except (ValidationError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid {ftype.value} content: {exc}")
    raise HTTPException(status_code=400, detail=f"feed type '{ftype.value}' not supported")


def _item_count(feed: Feed) -> int:
    if feed.type == FeedType.network_feed:
        return len(feed.content.get("entries", []))
    if feed.type == FeedType.ioc:
        if feed.content.get("format") == "snort":
            return len(feed.content.get("rules", []))
        return len(feed.content.get("indicators", []))
    return len(feed.content.get("objects", []))


def _owned(db: Session, feed_id: int, user: User) -> Feed:
    feed = db.get(Feed, feed_id)
    if feed is None or feed.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed


def feed_to_dict(feed: Feed) -> dict:
    return {
        "id": feed.id,
        "type": feed.type.value,
        "name": feed.name,
        "description": feed.description,
        "token": feed.token,
        "url": public_url(feed),
        "interval_seconds": feed.interval_seconds,
        "auth_required": bool(feed.auth_header_key),
        "item_count": _item_count(feed),
        "created_at": feed.created_at.isoformat(),
        "updated_at": feed.updated_at.isoformat(),
    }


@router.post("/feeds", status_code=201)
def create_feed(body: FeedCreate, user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    content = _build_content(
        body.type,
        objects=body.objects,
        entries=body.entries,
        feed_format=body.feed_format,
        data_type=body.data_type,
        json_body=body.json_body,
        jq_query=body.jq_query,
        indicators=body.indicators,
        ioc_format=body.ioc_format,
        snort_rules=body.snort_rules,
        ioc_delimiter=body.ioc_delimiter,
        ioc_comment=body.ioc_comment,
        description=body.description,
    )
    feed = Feed(
        token=new_feed_token(),
        type=body.type,
        name=body.name,
        description=body.description,
        content=content,
        interval_seconds=body.interval_seconds,
        auth_header_key=body.auth_header_key or None,
        auth_header_value=body.auth_header_value or None,
        owner_id=user.id,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    return feed_to_dict(feed)


@router.get("/feeds")
def list_feeds(user: User = Depends(current_user), db: Session = Depends(get_db)) -> list[dict]:
    feeds = db.scalars(
        select(Feed).where(Feed.owner_id == user.id).order_by(Feed.created_at.desc())
    ).all()
    return [feed_to_dict(f) for f in feeds]


@router.get("/feeds/{feed_id}")
def get_feed(feed_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)) -> dict:
    feed = _owned(db, feed_id, user)
    data = feed_to_dict(feed)
    data["content"] = feed.content
    return data


@router.put("/feeds/{feed_id}")
def update_feed(
    feed_id: int, body: FeedUpdate, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> dict:
    feed = _owned(db, feed_id, user)
    if body.name is not None:
        feed.name = body.name
    if body.description is not None:
        feed.description = body.description
    if body.interval_seconds is not None:
        feed.interval_seconds = body.interval_seconds
    if body.auth_header_key is not None:
        feed.auth_header_key = body.auth_header_key or None
    if body.auth_header_value is not None:
        feed.auth_header_value = body.auth_header_value or None
    if body.objects is not None and feed.type == FeedType.generic_dc:
        feed.content = _build_content(feed.type, objects=body.objects, description=feed.description)
    if feed.type == FeedType.ioc and (body.indicators is not None or body.snort_rules is not None):
        fmt = body.ioc_format or feed.content.get("format", "cp_csv")
        feed.content = _build_content(
            feed.type, indicators=body.indicators or [], ioc_format=fmt,
            snort_rules=body.snort_rules or "",
            ioc_delimiter=body.ioc_delimiter if body.ioc_delimiter is not None else feed.content.get("delimiter", ","),
            ioc_comment=body.ioc_comment if body.ioc_comment is not None else feed.content.get("comment", "#"),
            description=feed.description)
    if feed.type == FeedType.network_feed and (body.entries is not None or body.json_body is not None):
        feed.content = _build_content(
            feed.type,
            entries=body.entries or [],
            feed_format=feed.content.get("format", "flat"),
            data_type=feed.content.get("data_type", "ip_domain"),
            json_body=body.json_body or "",
            jq_query=body.jq_query if body.jq_query is not None else feed.content.get("jq_query", ""),
            description=feed.description,
        )
    db.commit()
    db.refresh(feed)
    return feed_to_dict(feed)


@router.delete("/feeds/{feed_id}", status_code=204)
def delete_feed(feed_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    feed = _owned(db, feed_id, user)
    db.delete(feed)
    db.commit()
    return Response(status_code=204)


@router.get("/feeds/{feed_id}/preview")
def preview_feed(feed_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)) -> Response:
    """Return exactly what the gateway would fetch — for the 'what will CP see?' panel."""
    feed = _owned(db, feed_id, user)
    body, media = render_feed(feed)
    return Response(content=body, media_type=media)


@router.get("/feeds/{feed_id}/polls")
def feed_polls(
    feed_id: int, limit: int = 25, user: User = Depends(current_user), db: Session = Depends(get_db)
) -> list[dict]:
    feed = _owned(db, feed_id, user)
    return [
        {
            "at": p.at.isoformat(),
            "source_ip": p.source_ip,
            "user_agent": p.user_agent,
            "status": p.status,
        }
        for p in feed.polls[:limit]
    ]
