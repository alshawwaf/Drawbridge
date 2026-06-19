"""Build the public feed URL/path the SE pastes into SmartConsole."""
from .config import get_settings
from .models import Feed, FeedType

_PATHS = {
    FeedType.generic_dc: "/gdc/{token}.json",
    FeedType.ioc: "/ioc/{token}.csv",
    FeedType.network_feed: "/netfeed/{token}",
}

# IoC feeds serve different wire formats; the URL extension follows the chosen format (cosmetic —
# the gateway picks the format in its feed object, but a matching extension reads correctly).
_IOC_EXT = {"stix_1.x": "xml", "snort": "txt"}


def public_path(feed: Feed) -> str:
    if feed.type == FeedType.ioc:
        ext = _IOC_EXT.get((feed.content or {}).get("format"), "csv")
        return f"/ioc/{feed.token}.{ext}"
    return _PATHS[feed.type].format(token=feed.token)


def public_url(feed: Feed) -> str:
    return get_settings().base_url.rstrip("/") + public_path(feed)
