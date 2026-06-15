"""ORM models: portal users, simulated feeds, and the live poll log."""
import datetime as dt
import enum
import uuid

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def new_uuid() -> str:
    return str(uuid.uuid4())


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class FeedType(str, enum.Enum):
    generic_dc = "generic_dc"
    ioc = "ioc"
    network_feed = "network_feed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    feeds: Mapped[list["Feed"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Feed(Base):
    __tablename__ = "feeds"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Long random token = the unguessable, public feed URL segment.
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    type: Mapped[FeedType] = mapped_column(Enum(FeedType))
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")

    # Type-specific payload. For generic_dc: {"objects": [{name, id, description, ranges:[...]}]}.
    content: Mapped[dict] = mapped_column(JSON, default=dict)

    # Optional per-feed auth that the gateway must satisfy when polling:
    #  - Generic DC uses a Custom Header (key/value).
    #  - Network Feed uses HTTP basic auth (stored in auth_header_key/value as user/pass).
    auth_header_key: Mapped[str | None] = mapped_column(String(120), nullable=True)
    auth_header_value: Mapped[str | None] = mapped_column(String(255), nullable=True)

    interval_seconds: Mapped[int] = mapped_column(Integer, default=10)

    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    owner: Mapped["User"] = relationship(back_populates="feeds")
    polls: Mapped[list["FeedPoll"]] = relationship(
        back_populates="feed", cascade="all, delete-orphan", order_by="FeedPoll.at.desc()"
    )


class FeedPoll(Base):
    """One recorded fetch of a feed — the evidence that the gateway is live-syncing."""

    __tablename__ = "feed_polls"

    id: Mapped[int] = mapped_column(primary_key=True)
    feed_id: Mapped[int] = mapped_column(ForeignKey("feeds.id"), index=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[int] = mapped_column(Integer, default=200)

    feed: Mapped["Feed"] = relationship(back_populates="polls")
