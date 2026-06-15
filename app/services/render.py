"""Render a stored Feed into the exact wire format the gateway fetches."""
import json
import uuid

from ..models import Feed, FeedType
from ..schemas.generic_dc import GDCObjectIn, GENERIC_DC_VERSION
from ..schemas.network_feed import NetworkFeedConfig, validate_entry


def normalize_generic_dc_content(objects: list[dict], description: str = "") -> dict:
    """Validate SE-entered objects and assign a stable UUID to any without one.

    Returns the dict persisted in Feed.content. Raises pydantic ValidationError /
    ValueError on malformed input so the API can surface a clean 422.
    """
    normalized = []
    seen_ids: set[str] = set()
    for raw in objects:
        obj = GDCObjectIn.model_validate(raw)
        oid = obj.id or str(uuid.uuid4())
        while oid in seen_ids:  # guarantee uniqueness even if caller supplied dupes
            oid = str(uuid.uuid4())
        seen_ids.add(oid)
        normalized.append(
            {"name": obj.name, "id": oid, "description": obj.description, "ranges": obj.ranges}
        )
    return {"objects": normalized}


def render_generic_dc(feed: Feed) -> tuple[str, str]:
    doc: dict = {"version": GENERIC_DC_VERSION}
    if feed.description:
        doc["description"] = feed.description
    out = []
    for o in feed.content.get("objects", []):
        # Key order mirrors the sk167210 example: name, id, description, ranges.
        item: dict = {"name": o["name"], "id": o.get("id") or str(uuid.uuid4())}
        if o.get("description"):
            item["description"] = o["description"]
        item["ranges"] = o["ranges"]
        out.append(item)
    doc["objects"] = out
    return json.dumps(doc, indent=2), "application/json"


def normalize_network_feed_content(entries: list[str], data_type: str, fmt: str) -> dict:
    """Validate Network Feed config + entries; returns the dict persisted in Feed.content.

    Entry validation lives here (not in the pydantic model) so a bad entry raises a clean,
    readable ValueError instead of a verbose pydantic ValidationError dump.
    """
    cfg = NetworkFeedConfig(format=fmt, data_type=data_type, entries=entries)
    validated = [validate_entry(e, cfg.data_type) for e in cfg.entries]
    return {"format": cfg.format, "data_type": cfg.data_type, "entries": validated}


def render_network_feed(feed: Feed) -> tuple[str, str]:
    entries = feed.content.get("entries", [])
    if feed.content.get("format") == "json":
        return json.dumps({"entries": entries}, indent=2), "application/json"
    # Flat list: one entry per line.
    return "\n".join(entries) + "\n", "text/plain; charset=utf-8"


def render_feed(feed: Feed) -> tuple[str, str]:
    """Dispatch to the per-type renderer. Returns (body, media_type)."""
    if feed.type == FeedType.generic_dc:
        return render_generic_dc(feed)
    if feed.type == FeedType.network_feed:
        return render_network_feed(feed)
    # IoC (M2) renderer slots in here.
    raise NotImplementedError(f"rendering not implemented for feed type {feed.type.value}")
