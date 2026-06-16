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


class DynamicLayer(Base):
    """An authored Dynamic Layer policy, stored on the portal and applied to a gateway
    (real or the built-in mock) via the Gaia API 'set-dynamic-content'."""

    __tablename__ = "dynamic_layers"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    # The access-layer name on the gateway (must be marked "Set as a Dynamic Layer").
    layer_name: Mapped[str] = mapped_column(String(200), default="dynamic_layer")
    # Authored payload: {objects:{type:[...]}, rulebase:[...], referenced_objects:{...},
    #                    operation, comments, tags, custom_fields}
    content: Mapped[dict] = mapped_column(JSON, default=dict)

    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    tasks: Mapped[list["LayerTask"]] = relationship(
        back_populates="layer", cascade="all, delete-orphan", order_by="LayerTask.at.desc()"
    )


class LayerTask(Base):
    """A recorded set-dynamic-content apply (to the mock or a real gateway) and its result —
    mirrors the Gaia API async task / show-task response."""

    __tablename__ = "layer_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    task_id: Mapped[str] = mapped_column(String(64), index=True)
    layer_id: Mapped[int | None] = mapped_column(
        ForeignKey("dynamic_layers.id"), nullable=True, index=True
    )
    target: Mapped[str] = mapped_column(String(32), default="mock")  # mock | gateway
    gateway_host: Mapped[str | None] = mapped_column(String(200), nullable=True)
    dry_run: Mapped[bool] = mapped_column(default=False)
    status: Mapped[str] = mapped_column(String(32), default="succeeded")
    status_code: Mapped[int] = mapped_column(Integer, default=200)
    # show-task-style payload: {change_summary, validation_warnings, validation_errors, ...}
    result: Mapped[dict] = mapped_column(JSON, default=dict)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    user_agent: Mapped[str] = mapped_column(String(255), default="")

    layer: Mapped["DynamicLayer"] = relationship(back_populates="tasks")


class ActivityLog(Base):
    """App-wide log of integration traffic — feed polls, mock Gaia API calls, and layer
    applies — each with the actual (redacted) request/response for troubleshooting + demos."""

    __tablename__ = "activity_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)
    kind: Mapped[str] = mapped_column(String(32), index=True)  # feed_poll|gaia_mock|layer_apply
    direction: Mapped[str] = mapped_column(String(12), default="inbound")  # inbound|outbound
    method: Mapped[str] = mapped_column(String(10), default="")
    path: Mapped[str] = mapped_column(String(400), default="")
    source_ip: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[int] = mapped_column(Integer, default=0)
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(String(300), default="")
    detail: Mapped[dict] = mapped_column(JSON, default=dict)  # {request:{...}, response:{...}} or {trace}


class Gateway(Base):
    """A saved gateway connection profile. The login password is optional: if set it is stored
    AES-256-GCM-encrypted in a separate table (GatewaySecret); otherwise it is entered per apply.
    Optionally pins a self-signed cert (PEM) for TLS verification."""

    __tablename__ = "gateways"

    id: Mapped[int] = mapped_column(primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    host: Mapped[str] = mapped_column(String(200))
    port: Mapped[int] = mapped_column(Integer, default=443)
    username: Mapped[str] = mapped_column(String(120), default="")
    cert_pem: Mapped[str] = mapped_column(Text, default="")
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    snapshot: Mapped["GatewayLayerSnapshot"] = relationship(
        back_populates="gateway", cascade="all, delete-orphan", uselist=False)
    secret: Mapped["GatewaySecret"] = relationship(
        back_populates="gateway", cascade="all, delete-orphan", uselist=False)


class GatewaySecret(Base):
    """The optional gateway login password, encrypted at rest with AES-256-GCM (org policy:
    credentials at rest must use AES-256 or stronger). Kept in its own table so the secret is
    never loaded or serialized alongside the gateway profile unless an apply/fetch needs it."""

    __tablename__ = "gateway_secrets"

    id: Mapped[int] = mapped_column(primary_key=True)
    gateway_id: Mapped[int] = mapped_column(ForeignKey("gateways.id"), unique=True, index=True)
    # Versioned, base64-encoded AES-256-GCM token (nonce + ciphertext + tag). Never the plaintext.
    ciphertext: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    gateway: Mapped["Gateway"] = relationship(back_populates="secret")


class GatewayLayerSnapshot(Base):
    """Persisted snapshot of the dynamic layers last fetched from a gateway (show-dynamic-layers /
    show-dynamic-layer), so the 'what's on this gateway' view survives the fetch modal closing."""

    __tablename__ = "gateway_layer_snapshots"

    id: Mapped[int] = mapped_column(primary_key=True)
    gateway_id: Mapped[int] = mapped_column(ForeignKey("gateways.id"), unique=True, index=True)
    layers: Mapped[list] = mapped_column(JSON, default=list)
    ok: Mapped[bool] = mapped_column(default=True)
    error: Mapped[str] = mapped_column(Text, default="")
    fetched_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    gateway: Mapped["Gateway"] = relationship(back_populates="snapshot")


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
