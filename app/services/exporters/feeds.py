"""Export builder: the Feeds dashboard (every simulated feed the signed-in SE owns)."""
from sqlalchemy import select

from ...links import public_url
from ...models import Feed, FeedType
from ..exporting import ExportTable, fmt_dt, register


def _count_label(feed: Feed) -> str:
    # Mirror routers.ui._count_label / _item_count exactly.
    content = feed.content or {}
    if feed.type == FeedType.network_feed:
        if content.get("format") == "json":
            return "—"
        return str(len(content.get("entries", [])))
    if feed.type == FeedType.ioc:
        if content.get("format") == "snort":
            return str(len(content.get("rules", [])))
        return str(len(content.get("indicators", [])))
    return str(len(content.get("objects", [])))


_DT_LABELS = {"ip": "IP", "domain": "Domain", "ip_domain": "IP/Domain"}


def _type_label(feed: Feed) -> str:
    # The table shows the raw enum value as a pill, with a format/data-type sub-line for network feeds.
    label = feed.type.value
    if feed.type == FeedType.network_feed:
        content = feed.content or {}
        fmt = "JSON" if content.get("format") == "json" else "Flat list"
        sub = f"{fmt} · {_DT_LABELS.get(content.get('data_type', ''), '')}"
        return f"{label} ({sub})"
    return label


def _auth_label(feed: Feed) -> str:
    if not feed.auth_header_key:
        return "open"
    return "header" if feed.type == FeedType.generic_dc else "basic"


@register("feeds")
def build(db, user, qp) -> ExportTable:
    feeds = db.scalars(
        select(Feed).where(Feed.owner_id == user.id).order_by(Feed.created_at.desc())
    ).all()

    columns = ["Name", "Type", "Items", "Interval", "Auth", "Feed URL", "Created"]
    rows = [[
        f.name,
        _type_label(f),
        _count_label(f),
        f.interval_seconds,
        _auth_label(f),
        public_url(f),
        fmt_dt(f.created_at),
    ] for f in feeds]

    return ExportTable(
        title="Simulated feeds",
        columns=columns,
        rows=rows,
        subtitle="Every simulated feed and the public URL the gateway polls.",
        numeric_cols={2, 3},
    )
