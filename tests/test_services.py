"""Service-name correlation: resolve any CP service type by name, confident-unique only, with the same
truncation/dedup safety as applications."""
import types

from app.services import services as sv


def _svc(name, uid=None, typ="service-icmp"):
    return {"name": name, "uid": uid or name, "type": typ}


class _Sess:
    def __init__(self, objs):
        self._o = objs
        self.server = types.SimpleNamespace(host="h", port=443, domain="")

    def call(self, cmd, payload=None):
        return {"objects": self._o} if cmd == "show-objects" else {}


def test_search_keeps_only_service_objects():
    sv._cache.clear()
    s = _Sess([_svc("echo-request"), {"name": "echo-host", "uid": "h1", "type": "host"}])
    cands = sv.search(s, "echo")
    assert len(cands) == 1 and cands[0]["name"] == "echo-request"   # the host is filtered out


def test_exact_and_normalized_service_match():
    sv._cache.clear()
    assert sv.resolve(_Sess([_svc("echo-request"), _svc("echo-reply")]), "echo-request")["confidence"] == "exact"
    sv._cache.clear()
    assert sv.resolve(_Sess([_svc("GRE", typ="service-other")]), "gre")["confidence"] == "exact"  # case-insensitive
    sv._cache.clear()
    r = sv.resolve(_Sess([_svc("echo-request")]), "echo request")   # space vs hyphen -> normalized
    assert r["match"] == "echo-request" and r["confidence"] == "normalized"


def test_ambiguous_services_no_auto_match():
    sv._cache.clear()
    s = _Sess([_svc("ICMP", typ="service-icmp"), _svc("icmp", typ="service-other")])  # both -> "icmp"
    r = sv.resolve(s, "icmp")
    assert r["match"] is None and len(r["candidates"]) >= 2


def test_truncated_services_never_auto_match():
    sv._cache.clear()
    flood = [_svc("GRE", typ="service-other")] + [_svc("svc%d" % i, uid="u%d" % i) for i in range(sv._RESOLVE_LIMIT)]
    assert sv.resolve(_Sess(flood), "GRE")["match"] is None


def test_no_service_match():
    sv._cache.clear()
    r = sv.resolve(_Sess([]), "totally-unknown-zzz")
    assert r["match"] is None and r["candidates"] == [] and r["note"]


def test_kind_filter_restricts_to_picked_service_type():
    sv._cache.clear()
    objs = [_svc("echo-request", typ="service-icmp"),
            _svc("echo-request6", typ="service-icmp6"),
            _svc("GRE", typ="service-other"),
            _svc("https", typ="service-tcp")]
    s = _Sess(objs)
    # icmp keeps BOTH icmp families, drops other/tcp
    icmp = {c["name"] for c in sv.search(s, "echo", kind="icmp")}
    assert icmp == {"echo-request", "echo-request6"}
    sv._cache.clear()
    # "other" keeps only service-other
    other = [c["name"] for c in sv.search(_Sess(objs), "GRE", kind="other")]
    assert other == ["GRE"]
    sv._cache.clear()
    # no kind -> unfiltered (all service-*)   (_Sess ignores the server-side filter; term only gates len>=2)
    allk = {c["name"] for c in sv.search(_Sess(objs), "ec", kind="")}
    assert "https" in allk and "GRE" in allk


def test_kind_is_part_of_the_cache_key():
    sv._cache.clear()
    objs = [_svc("echo-request", typ="service-icmp"), _svc("GRE", typ="service-other")]
    s = _Sess(objs)
    assert len(sv.search(s, "ec", kind="icmp")) == 1          # icmp only
    assert "GRE" in {c["name"] for c in sv.search(s, "ec", kind="")}   # different key -> not the cached icmp result
