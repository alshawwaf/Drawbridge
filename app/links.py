"""Build the public feed URL/path the SE pastes into SmartConsole."""
from .config import get_settings
from .models import Feed, FeedType

_PATHS = {
    FeedType.generic_dc: "/gdc/{token}.json",
    FeedType.ioc: "/ioc/{token}.csv",
    FeedType.network_feed: "/netfeed/{token}",
}


def public_path(feed: Feed) -> str:
    return _PATHS[feed.type].format(token=feed.token)


def public_url(feed: Feed) -> str:
    return get_settings().base_url.rstrip("/") + public_path(feed)
