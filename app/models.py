"""ORM models: portal users, simulated feeds, and the live poll log."""
import datetime as dt
import enum
import uuid

from sqlalchemy import JSON, Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint
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
    first_name: Mapped[str] = mapped_column(String(80), default="")
    last_name: Mapped[str] = mapped_column(String(80), default="")
    email: Mapped[str] = mapped_column(String(200), default="")
    title: Mapped[str] = mapped_column(String(120), default="")          # role / job title
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    feeds: Mapped[list["Feed"]] = relationship(back_populates="owner", cascade="all, delete-orphan")

    @property
    def display_name(self) -> str:
        return (f"{self.first_name} {self.last_name}".strip()) or self.username


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


class ActivityLog(Base):
    """App-wide log of integration traffic — feed polls and mock provider/API calls — each with the
    actual (redacted) request/response for troubleshooting + demos."""

    __tablename__ = "activity_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # feed_poll | datacenter | siem | api | ui
    direction: Mapped[str] = mapped_column(String(12), default="inbound")  # inbound|outbound
    method: Mapped[str] = mapped_column(String(10), default="")
    path: Mapped[str] = mapped_column(String(400), default="")
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(String(300), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # {request:{...}, response:{...}} or {trace}


class SiemLog(Base):
    """A log line received by the built-in SIEM receiver from Check Point's Log Exporter (syslog /
    CEF / LEEF / JSON over TCP or UDP). Parsed best-effort into structured fields; the raw line is
    kept too. Not owner-scoped (logs arrive from gateways, like the ActivityLog)."""

    __tablename__ = "siem_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    transport: Mapped[str] = mapped_column(String(8), default="udp")     # udp | tcp
    fmt: Mapped[str] = mapped_column(String(16), default="syslog", index=True)  # cef|leef|json|syslog|raw
    severity: Mapped[str] = mapped_column(String(24), default="")
    host: Mapped[str] = mapped_column(String(120), default="")
    summary: Mapped[str] = mapped_column(String(400), default="")
    fields: Mapped[dict] = mapped_column(JSON, default=dict)
    raw: Mapped[str] = mapped_column(Text, default="")


class AppState(Base):
    """A tiny key→value store for cross-process runtime flags that must be shared across uvicorn
    workers / Swarm replicas (which each have their own memory) — e.g. the SIEM receiver's
    pause toggle. Kept in the DB so a Pause/Resume from any process reaches the listener's process."""

    __tablename__ = "app_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(String(255), default="")


class ApiKey(Base):
    """A named, revocable API key for the machine endpoints. Only the SHA-256 HASH of the secret is
    stored — the plaintext is shown once at creation and never again — so a DB leak exposes no usable
    key. ``scope`` says which endpoint the key authorizes; ``hint`` is the last few characters, kept
    for display so an admin can tell keys apart without revealing the secret."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    scope: Mapped[str] = mapped_column(String(20), default="api", index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # sha256 hex of the secret
    hint: Mapped[str] = mapped_column(String(12), default="")                   # last chars, for display
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(120), default="")
    last_used_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Notification(Base):
    """A persisted, per-user notification for the header bell. Every flash message is also recorded
    here so the admin can review and delete past notifications (transient toast + durable history)."""

    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    kind: Mapped[str] = mapped_column(String(16), default="success")   # success | error | info
    text: Mapped[str] = mapped_column(Text, default="")
    read: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


class LoginThrottle(Base):
    """Brute-force protection for the login form, keyed by CLIENT IP (never username — locking a
    username would let anyone DoS the admin out of their own portal). Too many failures -> a cooldown."""

    __tablename__ = "login_throttle"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)     # client IP
    fails: Mapped[int] = mapped_column(Integer, default=0)
    first_fail: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    locked_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class UserTablePref(Base):
    """Per-user, per-table view preferences (visible columns; later density/sort) so a chosen table
    view sticks across sessions/devices and is resolved server-side before first paint."""

    __tablename__ = "user_table_prefs"
    __table_args__ = (UniqueConstraint("owner_id", "table_id", name="uq_user_table"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    table_id: Mapped[str] = mapped_column(String(64))
    prefs: Mapped[dict] = mapped_column(JSON, default=dict)


class Datacenter(Base):
    """A mock cloud/datacenter that Check Point connects to (e.g. OpenStack). `content` holds
    the simulated inventory the provider API serves (instances, subnets, security groups)."""

    __tablename__ = "datacenters"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(32), default="openstack", index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    # openstack: {"instances":[{name,ip,tags,metadata}], "subnets":[{name,cidr}], "security_groups":[{name}]}
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    baseline: Mapped["DatacenterBaseline"] = relationship(
        back_populates="datacenter", cascade="all, delete-orphan", uselist=False)


class DatacenterBaseline(Base):
    """The inventory snapshot a datacenter resets to after a demo. Captured automatically before the
    first live mutation (and re-settable), so 'Reset to baseline' restores the pre-demo state."""

    __tablename__ = "datacenter_baselines"

    id: Mapped[int] = mapped_column(primary_key=True)
    datacenter_id: Mapped[int] = mapped_column(ForeignKey("datacenters.id"), unique=True, index=True)
    content: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    datacenter: Mapped["Datacenter"] = relationship(back_populates="baseline")
