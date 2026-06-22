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
