"""Correlate a requested service / protocol name to a real Check Point service object — icmp, GRE, AH,
ESP, sctp, dce-rpc, gtp, a tcp/udp service by name, … — so "icmp" maps to the actual predefined object
(e.g. "echo-request") or surfaces candidates, never a wrong / erroring reference.

Same safety + caching model as ``applications`` (and it reuses its matchers): one server-side search
(``show-objects`` filter, kept to ``service-*`` types — CP indexes the filter, no catalogue dump),
cached briefly; a local ranker that auto-uses ONLY a confident, UNIQUE exact / normalized-exact match
proven over a complete page. Anything ambiguous or truncated returns candidates for a human to pick."""
from __future__ import annotations

import time

from .applications import _norm, _score, _server_key   # shared, pure matchers

_TTL = 60.0
_cache: dict = {}
_RESOLVE_LIMIT = 200      # deep page so a duplicate can't hide past it (truncation guard, like apps)


def _query(session, term: str, limit: int) -> list[dict]:
    """All service-* objects matching ``term`` (one show-objects call, filtered client-side by type)."""
    try:
        r = session.call("show-objects", {"filter": term, "limit": limit, "details-level": "standard"})
        return [o for o in (r.get("objects") or []) if (o.get("type") or "").startswith("service-")]
    except Exception:  # noqa: BLE001 — best-effort; a failure just yields no candidates
        return []


def _candidates(objects: list[dict]) -> list[dict]:
    # Dedup on uid, falling back to (raw name, type) for uid-less objects so distinct names that merely
    # normalize alike stay separate (and visibly ambiguous) — same rule as applications._candidates.
    seen: set = set()
    out: list[dict] = []
    for o in objects:
        name = o.get("name")
        if not name:
            continue
        key = o.get("uid") or (name, o.get("type") or "")
        if key in seen:
            continue
        seen.add(key)
        out.append({"name": name, "uid": o.get("uid"),
                    "kind": (o.get("type") or "service").replace("service-", "")})
    return out


def search(session, term: str, limit: int = 40) -> list[dict]:
    """Candidate services matching ``term`` (for the UI type-ahead). Cached ~60s per (server, term)."""
    term = (term or "").strip()
    if len(term) < 2:
        return []
    key = (_server_key(session), term.lower(), limit)
    now = time.monotonic()
    hit = _cache.get(key)
    if hit and hit[0] > now:
        return hit[1]
    cands = _candidates(_query(session, term, limit))
    _cache[key] = (now + _TTL, cands)
    return cands


def resolve(session, term: str) -> dict:
    """Map ``term`` to a Check Point service. Returns {term, match, confidence, candidates, note}.
    ``match`` is set ONLY for a confident, UNIQUE exact / normalized-exact hit over a complete page; a
    truncated result is never auto-matched (a wrong service = wrong access)."""
    term = (term or "").strip()
    out = {"term": term, "match": None, "match_kind": "", "confidence": "", "candidates": [], "note": ""}
    if not term:
        return out
    raw = _query(session, term, _RESOLVE_LIMIT)
    truncated = len(raw) >= _RESOLVE_LIMIT
    scored = sorted(((_score(term, c["name"]), c) for c in _candidates(raw)),
                    key=lambda x: x[0][1], reverse=True)
    if not scored:
        out["note"] = f"No Check Point service matches “{term}”."
        return out
    exacts = [c for (lvl, _), c in scored if lvl == "exact"]
    norms = [c for (lvl, _), c in scored if lvl == "normalized"]
    win = exacts[0] if (not truncated and len(exacts) == 1) else \
        (norms[0] if (not truncated and not exacts and len(norms) == 1) else None)
    if win is not None:                 # carry the matched object's protocol family (icmp/icmp6/…) so
        out["match"], out["match_kind"] = win["name"], win["kind"]   # the engine can't alias families
        out["confidence"] = "exact" if exacts else "normalized"
    out["candidates"] = [{"name": c["name"], "kind": c["kind"], "score": round(sc, 2)}
                         for (lvl, sc), c in scored if sc >= 0.4][:8]
    if not out["match"]:
        out["note"] = (f"Too many matches for “{term}” — refine the name." if truncated
                       else (f"“{term}” is ambiguous — choose the exact Check Point service."
                             if out["candidates"] else f"No close match for “{term}”."))
    return out


def search_server(server, secret: str, term: str) -> list[dict]:
    from .mgmt_api import read_session
    with read_session(server, secret) as s:
        return search(s, term)
