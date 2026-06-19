"""Render a stored Feed into the exact wire format the gateway fetches."""
import csv
import io
import json
import uuid

from ..models import Feed, FeedType
from ..schemas.generic_dc import GDCObjectIn, GENERIC_DC_VERSION
from ..schemas.ioc import IndicatorIn
from ..schemas.network_feed import DATA_TYPES, validate_entry, validate_json_body

# Check Point native CSV column order (UNIQ-NAME first, then VALUE, TYPE, ...).
_IOC_COLUMNS = ("name", "value", "type", "confidence", "severity", "product", "comment")


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


def normalize_network_feed_flat(entries: list[str], data_type: str) -> dict:
    """Validate a flat list of entries; returns the dict persisted in Feed.content."""
    if data_type not in DATA_TYPES:
        raise ValueError(f"data_type must be one of {DATA_TYPES}")
    if not entries:
        raise ValueError("Enter at least one entry.")
    validated = [validate_entry(e, data_type) for e in entries]
    return {"format": "flat", "data_type": data_type, "entries": validated}


def normalize_network_feed_json(body: str, jq_query: str, data_type: str) -> dict:
    """Validate a custom JSON body + JQ query. The JSON is served verbatim to the gateway,
    which extracts values using the JQ query — so the structure is the SE's to design."""
    if data_type not in DATA_TYPES:
        raise ValueError(f"data_type must be one of {DATA_TYPES}")
    validate_json_body(body)
    query = (jq_query or "").strip()
    if not query:
        raise ValueError("Enter the JQ query the gateway uses to extract values from the JSON.")
    return {"format": "json", "data_type": data_type, "jq_query": query, "body": body}


def render_network_feed(feed: Feed) -> tuple[str, str]:
    content = feed.content
    if content.get("format") == "json":
        # Serve the SE's JSON exactly as authored.
        return content.get("body", ""), "application/json"
    # Flat list: one entry per line.
    return "\n".join(content.get("entries", [])) + "\n", "text/plain; charset=utf-8"


def normalize_ioc_content(indicators: list[dict], description: str = "") -> dict:
    """Validate SE-entered indicators (type/level tokens, per-type value, unique names).

    Returns the dict persisted in Feed.content. Raises pydantic ValidationError / ValueError on
    malformed input so the caller can surface a clean error.
    """
    normalized = []
    seen: set[str] = set()
    for raw in indicators:
        ind = IndicatorIn.model_validate(raw)
        if ind.name in seen:
            raise ValueError(f"duplicate indicator name {ind.name!r} — UNIQ-NAME must be unique")
        seen.add(ind.name)
        normalized.append({k: getattr(ind, k) for k in _IOC_COLUMNS})
    if not normalized:
        raise ValueError("Enter at least one indicator.")
    return {"indicators": normalized}


def render_ioc(feed: Feed) -> tuple[str, str]:
    """Emit the native Check Point IoC CSV: optional `#! DESCRIPTION` metadata, then positional rows.

    csv.writer quotes any field containing a comma/quote (e.g. a COMMENT), so the output round-trips.
    """
    buf = io.StringIO()
    desc = " ".join((feed.description or feed.name or "").split())
    if desc:
        buf.write(f"#! DESCRIPTION = {desc}\n")
    writer = csv.writer(buf, lineterminator="\n")
    for ind in feed.content.get("indicators", []):
        writer.writerow([ind.get(col, "") for col in _IOC_COLUMNS])
    return buf.getvalue(), "text/csv; charset=utf-8"


def render_feed(feed: Feed) -> tuple[str, str]:
    """Dispatch to the per-type renderer. Returns (body, media_type)."""
    if feed.type == FeedType.generic_dc:
        return render_generic_dc(feed)
    if feed.type == FeedType.network_feed:
        return render_network_feed(feed)
    if feed.type == FeedType.ioc:
        return render_ioc(feed)
    raise NotImplementedError(f"rendering not implemented for feed type {feed.type.value}")
