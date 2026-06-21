"""Public feed-serving endpoints — what the Check Point gateway/management polls.

These are intentionally unauthenticated at the portal level (the gateway must reach
them), guarded only by an unguessable token plus the optional per-feed credential the
SE configured. Every fetch is recorded as a FeedPoll to prove the sync is live.
"""
import base64
import hmac
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..models import Feed, FeedPoll, FeedType
from ..services.render import render_feed

router = APIRouter(tags=["feed-serving"])


def _client_ip(request: Request) -> str:
    # Behind a trusted reverse proxy (Caddy/Dokploy) X-Forwarded-For carries the real gateway IP, but a
    # direct client can spoof it — record it only when it's a well-formed address, else use the TCP peer,
    # so a garbage/spoofed header can't pollute the (informational) poll log.
    xff = request.headers.get("x-forwarded-for", "")
    peer = request.client.host if request.client else ""
    cand = xff.split(",")[0].strip() if xff else peer
    try:
        ipaddress.ip_address(cand)
        return cand
    except ValueError:
        return peer


def _record_poll(db: Session, feed: Feed, request: Request, status_code: int) -> None:
    try:
        db.add(
            FeedPoll(
                feed_id=feed.id,
                source_ip=_client_ip(request),
                user_agent=(request.headers.get("user-agent") or "")[:255],
                status=status_code,
            )
        )
        db.commit()
    except Exception:        # the poll log is best-effort — never fail the feed the gateway depends on
        db.rollback()


def _auth_ok(feed: Feed, request: Request) -> bool:
    if not feed.auth_header_key:
        return True
    got = request.headers.get(feed.auth_header_key)  # header lookup is case-insensitive
    return got is not None and hmac.compare_digest(got, feed.auth_header_value or "")


def _get_feed(db: Session, token: str, ftype: FeedType) -> Feed:
    feed = db.scalar(select(Feed).where(Feed.token == token, Feed.type == ftype))
    if feed is None:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed


@router.get("/gdc/{token}.json")
def serve_generic_dc(token: str, request: Request, db: Session = Depends(get_db)) -> Response:
    feed = _get_feed(db, token, FeedType.generic_dc)
    if not _auth_ok(feed, request):
        _record_poll(db, feed, request, 401)
        raise HTTPException(status_code=401, detail="Missing or invalid feed credentials")
    body, media = render_feed(feed)
    _record_poll(db, feed, request, 200)
    # no-cache so each poll reflects the latest edit immediately
    return Response(content=body, media_type=media, headers={"Cache-Control": "no-store"})


def _basic_auth_ok(feed: Feed, request: Request) -> bool:
    """Network Feed uses HTTP Basic auth (username in auth_header_key, password in value)."""
    if not feed.auth_header_key:
        return True
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("basic "):
        return False
    try:
        user, _, pw = base64.b64decode(header.split(" ", 1)[1]).decode().partition(":")
    except Exception:
        return False
    return hmac.compare_digest(user, feed.auth_header_key or "") and hmac.compare_digest(
        pw, feed.auth_header_value or ""
    )


@router.get("/netfeed/{token}")
def serve_network_feed(token: str, request: Request, db: Session = Depends(get_db)) -> Response:
    feed = _get_feed(db, token, FeedType.network_feed)
    if not _basic_auth_ok(feed, request):
        _record_poll(db, feed, request, 401)
        return Response(
            "Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="network-feed"'},
        )
    body, media = render_feed(feed)
    _record_poll(db, feed, request, 200)
    return Response(content=body, media_type=media, headers={"Cache-Control": "no-store"})


@router.get("/ioc/{token}.csv")   # native Check Point CSV / Custom CSV
@router.get("/ioc/{token}.xml")   # STIX 1.x
@router.get("/ioc/{token}.txt")   # Snort rules
def serve_ioc(token: str, request: Request, db: Session = Depends(get_db)) -> Response:
    feed = _get_feed(db, token, FeedType.ioc)
    if not _basic_auth_ok(feed, request):  # IoC feeds authenticate with --user_name (HTTP Basic, R81.20+)
        _record_poll(db, feed, request, 401)
        return Response(
            "Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": 'Basic realm="ioc-feed"'},
        )
    body, media = render_feed(feed)
    _record_poll(db, feed, request, 200)
    return Response(content=body, media_type=media, headers={"Cache-Control": "no-store"})
