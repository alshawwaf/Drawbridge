"""Ticket-driven access automation engine.

Turns an access request (source, destination, service) into the *minimal correct*
change on a Check Point access layer, via the Management web_api. Mirrors the
four-outcome model that FireMon / Tufin Designer / AlgoSec FireFlow converge on,
grounded in the Al-Shaer & Hamed five-relation algebra (IEEE JSAC 2005):

    NO_OP  - the flow is already permitted              -> change nothing
    WIDEN  - a rule already covers dst+svc, src differs -> extend its source
             (prefer a group the rule already references)
    CREATE - nothing covers it                          -> add a least-privilege
             rule above the cleanup / blocking drop, below any more-specific rule
    REVIEW - an explicit deny covers it, or a negated / unparsable rule lies in
             the path -> hand to a human (never silently override an admin's drop)

Design
------
* ``decide()`` is PURE (no I/O). It runs on already-parsed rules, so it is unit
  testable and drives the dry-run preview. Run this module directly
  (``python -m app.services.access_automation``) for an offline smoke test.
* The rulebase is pulled the same way ``mgmt_api.pull_for_export`` does it:
  ``show-access-rulebase`` with ``use-object-dictionary`` + ``details-level full``,
  then cells are resolved through the object dictionary to effective IP / port
  intervals. Comparisons are on values, never on object names.
* ``preview()`` is read-only. ``execute()`` writes inside ONE session and then
  publishes (commit) or discards (validate-only / on error) — same transactional
  shape as ``mgmt_api.apply_changes``.

VERIFY markers
--------------
Tokens tagged ``# VERIFY`` are exact web_api parameter spellings (e.g.
``members.add``, ``source.add``, ``position {above: uid}``). The *capability* is
confirmed by research; the precise spelling should be checked against a live
R82.10 management server (the SBT lab) before production use. IPv4 + tcp/udp only;
IPv6 / complex services fall through to REVIEW.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:  # keep the engine import-safe outside the app runtime (offline smoke test)
    from .mgmt_api import MgmtError, MgmtSession
except Exception:  # pragma: no cover
    MgmtSession = object  # type: ignore

    class MgmtError(Exception):
        pass


_V4_MAX = (1 << 32) - 1
ANY_IP: list[tuple[int, int]] = [(0, _V4_MAX)]


# --------------------------------------------------------------------------- #
# Interval math -- the Al-Shaer relation primitive (compare per field, by value)
# --------------------------------------------------------------------------- #
def _merge(iv):
    out: list[tuple[int, int]] = []
    for lo, hi in sorted(iv):
        if out and lo <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], hi))
        else:
            out.append((lo, hi))
    return out


def _covers(big, small) -> bool:
    """True if every interval in ``small`` is fully contained in ``big``."""
    for lo, hi in small:
        if not any(blo <= lo and hi <= bhi for blo, bhi in big):
            return False
    return True


def _overlaps(a, b) -> bool:
    return any(alo <= bhi and blo <= ahi for alo, ahi in a for blo, bhi in b)


class Relation(str, Enum):
    DISJOINT = "disjoint"
    EQUAL = "equal"
    SUBSET = "subset"      # request is contained by rule  (request <= rule)
    SUPERSET = "superset"  # request contains rule         (request >= rule)
    OVERLAP = "overlap"    # partial / correlated


def relation(req, rule) -> Relation:
    if not _overlaps(req, rule):
        return Relation.DISJOINT
    req_in_rule = _covers(rule, req)
    rule_in_req = _covers(req, rule)
    if req_in_rule and rule_in_req:
        return Relation.EQUAL
    if req_in_rule:
        return Relation.SUBSET
    if rule_in_req:
        return Relation.SUPERSET
    return Relation.OVERLAP


@dataclass
class ServiceSet:
    """The 'Services & Applications' cell: port services (proto -> port intervals), application-site
    names, an 'Any' flag, an 'opaque' flag (an app category/group we can't enumerate), the truly
    unparsable flag, and the service-group uids it references (for widening)."""
    any: bool = False
    by_proto: dict = field(default_factory=dict)
    apps: set = field(default_factory=set)        # exact application-site names (e.g. {"Facebook"})
    opaque: bool = False                          # has an app category/group we can't expand
    complex: bool = False                         # held a service we could not parse (named, >, < ...)
    group_uids: list = field(default_factory=list)  # service-group uids referenced (widen target)

    def covers(self, other: "ServiceSet") -> bool:
        if self.any:
            return True
        if other.any:
            return False
        for proto, iv in other.by_proto.items():
            mine = self.by_proto.get(proto)
            if not mine or not _covers(mine, iv):
                return False
        return True

    def overlaps(self, other: "ServiceSet") -> bool:
        if self.any or other.any:
            return True
        for proto, iv in other.by_proto.items():
            mine = self.by_proto.get(proto)
            if mine and _overlaps(mine, iv):
                return True
        return False


def _portset_covers(big: dict, small: dict) -> bool:
    for proto, iv in small.items():
        mine = big.get(proto)
        if not mine or not _covers(mine, iv):
            return False
    return True


def _portset_overlaps(a: dict, b: dict) -> bool:
    return any(proto in b and _overlaps(b[proto], iv) for proto, iv in a.items())


def svc_relation(req: ServiceSet, rule: ServiceSet) -> Relation:
    """Relate a request's service to a rule's 'Services & Applications' cell. A request is either
    port-based (by_proto) or application-based (apps); the two kinds are disjoint from each other.
    An opaque app container in the rule yields OVERLAP for a non-matching app request (uncertain)."""
    if rule.any and req.any:
        return Relation.EQUAL
    if rule.any:
        return Relation.SUBSET            # a specific request is a subset of Any
    if req.any:
        return Relation.SUPERSET
    if req.apps:                          # APPLICATION request, e.g. {"Facebook"}
        if req.apps & rule.apps:
            exact = rule.apps == req.apps and not rule.by_proto and not rule.opaque
            return Relation.EQUAL if exact else Relation.SUBSET
        return Relation.OVERLAP if rule.opaque else Relation.DISJOINT
    if not rule.by_proto:                 # PORT request vs an apps-only rule -> can't serve a port
        return Relation.DISJOINT
    a_in_b = _portset_covers(rule.by_proto, req.by_proto)
    b_in_a = _portset_covers(req.by_proto, rule.by_proto)
    # If the rule cell ALSO holds applications / an opaque container / an unparsable member, it grants
    # strictly more than the ports, so a pure-port request can never be EXACTLY EQUAL to it -- only a
    # SUBSET (still 'covered', so a genuine no-op stays a no-op). Returning EQUAL would let a widen treat
    # the service as an exact match and drag the rule's extra apps onto the new source/destination.
    rule_port_only = not (rule.apps or rule.opaque or rule.complex)
    if a_in_b and b_in_a:
        return Relation.EQUAL if rule_port_only else Relation.SUBSET
    if a_in_b:
        return Relation.SUBSET
    if b_in_a:
        return Relation.SUPERSET
    return Relation.OVERLAP if _portset_overlaps(req.by_proto, rule.by_proto) else Relation.DISJOINT


# --------------------------------------------------------------------------- #
# Request / rule / decision models
# --------------------------------------------------------------------------- #
@dataclass
class AccessRequest:
    src_cidrs: list[str]      # e.g. ["192.168.9.9/32"]
    dst_cidrs: list[str]
    protocol: str = "tcp"     # "tcp" | "udp" (ignored when `application` is set)
    ports: str = ""           # "443" or "8000-8100" (ignored when `application` is set)
    application: Optional[str] = None   # an application-site name (e.g. "Facebook") instead of a port
    action: str = "Accept"

    def src_iv(self):
        return _cidrs_to_iv(self.src_cidrs)

    def dst_iv(self):
        return _cidrs_to_iv(self.dst_cidrs)

    def svc(self) -> ServiceSet:
        if self.application:
            return ServiceSet(apps={self.application})
        return ServiceSet(by_proto={self.protocol.lower(): _ports_to_iv(self.ports)})


@dataclass
class ParsedRule:
    uid: str
    number: int
    name: str
    enabled: bool
    action: str
    src: list                                   # ip intervals
    dst: list
    svc: ServiceSet
    source_group_uids: list = field(default_factory=list)
    dest_group_uids: list = field(default_factory=list)
    complex: bool = False                       # negation / unresolved -> excluded from reuse
    # Per-cell "extent unknown": the cell was negated or held an object we could not resolve, so its
    # real reach is uncertain. Such a cell is never "provably disjoint" -> the rule stays in the path.
    src_unknown: bool = False
    dst_unknown: bool = False
    svc_unknown: bool = False

    @property
    def is_accept(self) -> bool:
        return self.action.lower() in ("accept", "allow")

    @property
    def is_drop(self) -> bool:
        return self.action.lower() in ("drop", "reject")

    @property
    def is_resolved_action(self) -> bool:
        """True only for a plain Accept/Drop we can reason about. An inline-layer rule's action resolves
        to the sub-layer name, and Ask/Inform/Client-Auth delegate elsewhere -- we can't evaluate those,
        so a rule with such an action that lies in the path must route to REVIEW."""
        return self.is_accept or self.is_drop


class Outcome(str, Enum):
    NO_OP = "no_op"
    WIDEN = "widen"
    CREATE = "create"
    REVIEW = "review"


@dataclass
class Decision:
    outcome: Outcome
    reason: str
    target_rule: Optional[ParsedRule] = None    # rule we reuse / widen / anchor on
    position: Optional[dict] = None             # internal placement hint (resolved at apply)
    widen_group_uid: Optional[str] = None       # group to add the object to, if that cell uses one
    widen_field: Optional[str] = None           # "source" | "destination" — the dimension to extend


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #
def _ip_int(addr: str) -> int:
    return int(ipaddress.IPv4Address(addr))


def _cidrs_to_iv(cidrs):
    iv = []
    for c in cidrs:
        net = ipaddress.ip_network(c, strict=False)
        iv.append((int(net.network_address), int(net.broadcast_address)))
    return _merge(iv)


def _ports_to_iv(spec: str):
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            out.append((int(lo), int(hi)))
        elif part:
            out.append((int(part), int(part)))
    return _merge(out)


def _deref(ref, objdict: dict) -> dict:
    """A rule cell holds object UIDs (use-object-dictionary) or inline dicts; resolve to the full obj."""
    if isinstance(ref, str):
        return objdict.get(ref) or {"uid": ref, "name": ref}
    if isinstance(ref, dict):
        return objdict.get(ref.get("uid")) or ref
    return {}


def _parse_net(cell, objdict: dict):
    """-> (ip intervals, complex?, [group uids found in this cell])."""
    iv, groups, cx = [], [], False
    for ref in cell or []:
        o = _deref(ref, objdict)
        t = o.get("type", "")
        name = (o.get("name") or "").lower()
        if t == "CpmiAnyObject" or name == "any":
            return ANY_IP, False, groups
        if t == "host":
            a = o.get("ipv4-address")
            iv.append((_ip_int(a), _ip_int(a))) if a else (cx := True)
        elif t == "network":
            sub = o.get("subnet4") or o.get("subnet")
            ml = o.get("mask-length4", o.get("mask-length"))
            if sub and ml is not None:
                net = ipaddress.ip_network(f"{sub}/{ml}", strict=False)
                iv.append((int(net.network_address), int(net.broadcast_address)))
            else:
                cx = True
        elif t == "address-range":
            f, l = o.get("ipv4-address-first"), o.get("ipv4-address-last")
            iv.append((_ip_int(f), _ip_int(l))) if (f and l) else (cx := True)
        elif t in ("group", "group-with-exclusion"):
            groups.append(o.get("uid", ""))
            sub_iv, sub_cx, _ = _parse_net(o.get("members", []), objdict)
            iv.extend(sub_iv)
            cx = cx or sub_cx or (t == "group-with-exclusion")
        else:
            cx = True
    return _merge(iv), cx, groups


def _parse_port(spec):
    spec = str(spec).strip()
    try:
        if "-" in spec:
            lo, hi = spec.split("-", 1)
            return [(int(lo), int(hi))]
        if spec.isdigit():
            return [(int(spec), int(spec))]
    except ValueError:
        return None
    return None  # ">1024", named, etc -> unparsable


def _parse_svc(cell, objdict: dict) -> ServiceSet:
    s = ServiceSet()
    for ref in cell or []:
        o = _deref(ref, objdict)
        t = o.get("type", "")
        name = o.get("name") or ""
        if t == "CpmiAnyObject" or name.lower() == "any":
            return ServiceSet(any=True)
        if t in ("service-tcp", "service-udp"):
            proto = "tcp" if t.endswith("tcp") else "udp"
            iv = _parse_port(o.get("port", ""))
            if iv is None:
                s.complex = True
            else:
                s.by_proto[proto] = _merge(s.by_proto.get(proto, []) + iv)
        elif t == "application-site":
            s.apps.add(name)
        elif t in ("application-site-category", "application-site-group"):
            s.opaque = True                 # can't enumerate which apps it contains
        elif t == "service-group":
            s.group_uids.append(o.get("uid", ""))
            sub = _parse_svc(o.get("members", []), objdict)
            if sub.any:
                return ServiceSet(any=True)
            for proto, iv in sub.by_proto.items():
                s.by_proto[proto] = _merge(s.by_proto.get(proto, []) + iv)
            s.apps |= sub.apps
            s.opaque = s.opaque or sub.opaque
            s.complex = s.complex or sub.complex
        else:
            s.complex = True
    return s


def _parse_rule(e, objdict: dict) -> ParsedRule:
    src, src_cx, src_groups = _parse_net(e.get("source", []), objdict)
    dst, dst_cx, dst_groups = _parse_net(e.get("destination", []), objdict)
    svc = _parse_svc(e.get("service", []), objdict)
    action = e.get("action")
    if isinstance(action, str):
        action = (objdict.get(action) or {}).get("name", action)
    elif isinstance(action, dict):
        action = action.get("name", "")
    # A cell's extent is "unknown" if it was negated OR held an object we could not resolve to IPs/ports.
    src_unknown = bool(src_cx or e.get("source-negate"))
    dst_unknown = bool(dst_cx or e.get("destination-negate"))
    svc_unknown = bool(svc.complex or e.get("service-negate"))
    return ParsedRule(
        uid=e.get("uid", ""),
        number=e.get("rule-number", e.get("number", 0)),
        name=e.get("name", ""),
        enabled=e.get("enabled", True),
        action=action or "",
        src=src, dst=dst, svc=svc,
        source_group_uids=src_groups, dest_group_uids=dst_groups,
        complex=bool(src_unknown or dst_unknown or svc_unknown),
        src_unknown=src_unknown, dst_unknown=dst_unknown, svc_unknown=svc_unknown,
    )


def _flatten(items):
    for it in items or []:
        if it.get("type") == "access-section":
            yield from _flatten(it.get("rulebase", []))
        else:
            yield it


# --------------------------------------------------------------------------- #
# The pure decision engine
# --------------------------------------------------------------------------- #
def _is_subset(rel_src, rel_dst, rel_svc) -> bool:
    sub = (Relation.SUBSET, Relation.EQUAL)
    return rel_src in sub and rel_dst in sub and rel_svc in sub


def _dim_covered(rel: Relation) -> bool:
    """One request dimension is covered by a rule cell when the request is a subset of (or equals) it."""
    return rel in (Relation.SUBSET, Relation.EQUAL)


def _svc_uncertain(req_svc: ServiceSet, rule_svc: ServiceSet) -> bool:
    """We can't tell whether a rule's opaque app container (category/group) covers an APPLICATION
    request that isn't an exact match -> treat that rule as unresolved (route to REVIEW) for this
    request. Port requests are unaffected (an app container doesn't grant ports)."""
    if rule_svc.any:
        return False
    if req_svc.apps and not (req_svc.apps & rule_svc.apps):
        return rule_svc.opaque
    return False


def _is_proper_superset(rel_src, rel_dst, rel_svc) -> bool:
    sup = (Relation.SUPERSET, Relation.EQUAL)
    all_equal = rel_src == rel_dst == rel_svc == Relation.EQUAL
    return rel_src in sup and rel_dst in sup and rel_svc in sup and not all_equal


def _is_catchall(r: ParsedRule) -> bool:
    return _covers(r.src, ANY_IP) and _covers(r.dst, ANY_IP) and r.svc.any


def _provably_disjoint(rel: Relation, unknown: bool) -> bool:
    """A dimension proves the rule is out of the request's path only if the cell was fully resolved
    AND is disjoint. An unknown (negated / unresolved) cell can never prove disjointness."""
    return (not unknown) and rel == Relation.DISJOINT


def decide(req: AccessRequest, rules: list[ParsedRule]) -> Decision:
    """Pure: pick the minimal correct change for ``req`` against ``rules``.

    Walks the rulebase top-down, honouring Check Point first-match semantics.
    """
    req_src, req_dst, req_svc = req.src_iv(), req.dst_iv(), req.svc()
    covering_drop: Optional[ParsedRule] = None   # the catch-all cleanup that floors placement
    widen_target: Optional[ParsedRule] = None    # reachable accept EQUAL in 2 dims, differing in the 3rd
    widen_field: Optional[str] = None            # the dimension to extend: source | destination | service
    lower_anchor: Optional[ParsedRule] = None     # last rule strictly more specific than req

    for r in rules:
        if not r.enabled:
            continue

        rel_src = relation(req_src, r.src)
        rel_dst = relation(req_dst, r.dst)
        rel_svc = svc_relation(req_svc, r.svc)

        # A rule is out of the request's path only if it is PROVABLY disjoint on some dimension. A cell
        # whose extent we could not resolve (zone, dynamic-object, negation, unknown service) is never
        # provably disjoint -- so a rule with such a cell stays in the path and routes to REVIEW below.
        # (This is the safety invariant: never reason past a rule whose real reach is unknown.)
        svc_uncertain = _svc_uncertain(req_svc, r.svc)
        interferes = not (_provably_disjoint(rel_src, r.src_unknown)
                          or _provably_disjoint(rel_dst, r.dst_unknown)
                          or _provably_disjoint(rel_svc, r.svc_unknown or svc_uncertain))

        if (r.complex or svc_uncertain or not r.is_resolved_action) and interferes:
            return Decision(
                Outcome.REVIEW,
                f"rule {r.number} ({r.name}) lies in the traffic path but can't be reasoned about "
                f"(negation, an unresolved object, an application category, or a non-Accept/Drop action "
                f"such as an inline layer) -- needs human review",
                target_rule=r,
            )

        # Past here, any rule we reuse / widen / anchor on is fully resolved (complex+interfering rules
        # already returned REVIEW above; complex+provably-disjoint rules are excluded explicitly below).
        fully_covers = not r.complex and _is_subset(rel_src, rel_dst, rel_svc)

        # (1) already permitted? first covering ACCEPT before any covering DROP wins.
        if fully_covers and r.is_accept and covering_drop is None:
            return Decision(
                Outcome.NO_OP,
                f"already permitted by rule {r.number} ({r.name})",
                target_rule=r,
            )

        # A covering DROP. The catch-all cleanup is a placement floor; a *specific* deny is an
        # intentional block -- never silently insert an allow above it.
        if fully_covers and r.is_drop and covering_drop is None:
            if _is_catchall(r):
                covering_drop = r
            else:
                return Decision(
                    Outcome.REVIEW,
                    f"traffic is explicitly denied by rule {r.number} ({r.name}); an allow "
                    f"above it would override an intentional block -- needs human review",
                    target_rule=r,
                )

        # A reachable DROP that overlaps the request but does NOT fully cover it partially blocks the
        # flow (e.g. a /32 deny inside a /24 request, or an overlapping range). We can neither grant the
        # request (it would override that intentional partial block) nor split it into allowed/denied
        # sub-flows -> REVIEW. (A fully-covering deny is handled above; the catch-all cleanup is excluded.)
        if (r.is_drop and not r.complex and covering_drop is None
                and interferes and not fully_covers and not _is_catchall(r)):
            return Decision(
                Outcome.REVIEW,
                f"rule {r.number} ({r.name}) partially denies the requested scope (an overlapping DROP "
                f"in the path); granting it would override that block -- needs human review",
                target_rule=r,
            )

        # (2) widen candidate: a reachable ACCEPT that is EXACTLY EQUAL to the request in two of the
        # three dimensions {source, destination, service} and differs in the third -> add the request's
        # value for that third dimension to the rule's CELL. The other two MUST be equal, not merely a
        # superset: a cell holds a set, and adding a value grants it combined with EVERY member of the
        # other cells. If a rule's source is {win_client, win_server} and only win_server was requested,
        # widening its destination would also grant win_client -> over-grant. Requiring equality (and
        # adding to the cell, never to a shared group) means we grant precisely src x dst x svc.
        if (widen_target is None and r.is_accept and not r.complex and not svc_uncertain
                and covering_drop is None):
            eq = {"source": rel_src == Relation.EQUAL, "destination": rel_dst == Relation.EQUAL,
                  "service": rel_svc == Relation.EQUAL}
            cov = {"source": _dim_covered(rel_src), "destination": _dim_covered(rel_dst),
                   "service": _dim_covered(rel_svc)}
            not_covered = [d for d in ("source", "destination", "service") if not cov[d]]
            if len(not_covered) == 1:
                field = not_covered[0]
                if all(eq[d] for d in ("source", "destination", "service") if d != field):
                    widen_target, widen_field = r, field

        # Placement lower bound: a fully-resolved rule strictly MORE specific than req (don't shadow it).
        if not r.complex and _is_proper_superset(rel_src, rel_dst, rel_svc):
            lower_anchor = r

    if widen_target is not None:
        others = {"source": "destination + service", "destination": "source + service",
                  "service": "source + destination"}[widen_field]
        return Decision(
            Outcome.WIDEN,
            f"rule {widen_target.number} ({widen_target.name}) matches the request's {others} exactly; "
            f"add the {widen_field} to that rule",
            target_rule=widen_target, widen_field=widen_field,
        )

    return Decision(
        Outcome.CREATE,
        "no rule covers the request; create a least-privilege rule",
        target_rule=covering_drop or lower_anchor,
        position=_placement(covering_drop, lower_anchor),
    )


def _placement(covering_drop, lower_anchor) -> dict:
    """Internal placement hint, resolved to a web_api 'position' at apply time."""
    if (covering_drop is not None and lower_anchor is not None
            and lower_anchor.number > covering_drop.number):
        # the more-specific rule sits BELOW the cleanup -> existing anomaly worth flagging.
        return {"above": covering_drop.uid, "_anomaly": True}
    if covering_drop is not None:
        return {"above": covering_drop.uid}
    if lower_anchor is not None:
        return {"below": lower_anchor.uid}
    return {"_above_cleanup": True}


# --------------------------------------------------------------------------- #
# I/O layer  (uses the existing MgmtSession client)
# --------------------------------------------------------------------------- #
def load_layer(session, layer_name: str, package: Optional[str] = None,
               max_rules: int = 5000) -> list[ParsedRule]:
    """Pull a layer with full object details (same pattern as mgmt_api.pull_for_export) and parse
    every rule into value-resolved intervals."""
    items: list[dict] = []
    objdict: dict = {}
    total, offset = 0, 0
    while offset < max_rules:
        payload = {"name": layer_name, "limit": 100, "offset": offset,
                   "use-object-dictionary": True, "details-level": "full"}
        if package:
            payload["package"] = package
        page = session.call("show-access-rulebase", payload)
        for o in page.get("objects-dictionary", []):
            if o.get("uid"):
                objdict[o["uid"]] = o
        batch = page.get("rulebase", [])
        items.extend(batch)
        total = page.get("total", total)
        to = page.get("to", 0)
        if not batch or to >= total or to <= offset:
            break
        offset = to
    return [_parse_rule(e, objdict) for e in _flatten(items) if e.get("type") == "access-rule"]


def lookup_host(session, ip: str) -> Optional[str]:
    """Existing host object name for this exact IP, or None. Read-only (dedup by value)."""
    found = session.call("show-objects",
                         {"filter": ip, "ip-only": True, "type": "host", "limit": 5})  # VERIFY
    for o in found.get("objects", []):
        if o.get("ipv4-address") == ip:
            return o["name"]
    return None


def resolve_host(session, ip: str, name_hint: Optional[str] = None) -> str:
    """Reuse an existing host by exact IP, else create one."""
    existing = lookup_host(session, ip)
    if existing:
        return existing
    name = name_hint or f"h-{ip.replace('.', '-')}"
    session.call("add-host", {"name": name, "ip-address": ip})            # VERIFY
    return name


def _endpoint_name(net) -> str:
    base = str(net.network_address).replace(".", "-").replace(":", "-")
    return f"h-{base}" if net.prefixlen == net.max_prefixlen else f"n-{base}-{net.prefixlen}"


def lookup_network(session, net) -> Optional[str]:
    """Existing network object name matching this subnet + prefix, or None (dedup by value)."""
    sub_key = "subnet6" if net.version == 6 else "subnet4"
    mask_key = "mask-length6" if net.version == 6 else "mask-length4"
    found = session.call("show-objects",
                         {"filter": str(net.network_address), "type": "network", "limit": 25})  # VERIFY
    for o in found.get("objects", []):
        if str(o.get(sub_key)) == str(net.network_address) and int(o.get(mask_key, -1)) == net.prefixlen:
            return o["name"]
    return None


def lookup_endpoint(session, cidr: str) -> Optional[str]:
    """Existing object for a request endpoint — a host for /32 & /128, else a network — or None."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen == net.max_prefixlen:
        return lookup_host(session, str(net.network_address))
    return lookup_network(session, net)


def resolve_endpoint(session, cidr: str) -> str:
    """Reuse-or-create the object that represents a request endpoint. Critically, a CIDR wider than a
    single address materializes as a NETWORK object (not a /32 host), so the committed rule covers the
    full requested scope that decide() reasoned over — never silently narrowed to one IP."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen == net.max_prefixlen:
        return resolve_host(session, str(net.network_address), name_hint=_endpoint_name(net))
    existing = lookup_network(session, net)
    if existing:
        return existing
    name = _endpoint_name(net)
    addr = str(net.network_address)
    if net.version == 6:
        session.call("add-network", {"name": name, "subnet6": addr, "mask-length6": net.prefixlen})  # VERIFY
    else:
        session.call("add-network", {"name": name, "subnet4": addr, "mask-length4": net.prefixlen})  # VERIFY
    return name


def lookup_service(session, protocol: str, port: str) -> Optional[str]:
    """Existing service object name for this exact port/proto (incl. predefined), or None."""
    proto = protocol.lower()
    found = session.call(f"show-services-{proto}", {"filter": str(port), "limit": 25})  # VERIFY
    for o in found.get("objects", []):
        if str(o.get("port")) == str(port):
            return o["name"]
    return None


def resolve_service(session, protocol: str, port: str, name_hint: Optional[str] = None) -> str:
    proto = protocol.lower()
    existing = lookup_service(session, proto, port)
    if existing:
        return existing
    name = name_hint or f"{proto.upper()}-{port}"
    session.call(f"add-service-{proto}", {"name": name, "port": str(port)})  # VERIFY
    return name


def lookup_application(session, name: str) -> bool:
    """Whether a predefined/custom application-site by this exact name exists (best-effort)."""
    try:
        found = session.call("show-objects",
                             {"filter": name, "type": "application-site", "limit": 5})  # VERIFY
    except MgmtError:
        return False
    return any((o.get("name") or "") == name for o in found.get("objects", []))


def _resolve_svc_object(session, req: AccessRequest) -> str:
    """The object to put in the rule's 'Services & Applications' cell: an application-site referenced by
    name (predefined; the publish validates it), or a reused/created port service."""
    if req.application:
        return req.application
    return resolve_service(session, req.protocol, req.ports)


def _svc_object_preview(session, req: AccessRequest) -> dict:
    if req.application:
        return {"name": req.application, "exists": lookup_application(session, req.application),
                "kind": "application"}
    ex = lookup_service(session, req.protocol, req.ports)
    return {"name": ex or f"{req.protocol.upper()}-{req.ports}", "exists": bool(ex), "kind": "service"}


def _brief(rule: Optional[ParsedRule]) -> Optional[dict]:
    if not rule:
        return None
    return {"number": rule.number, "name": rule.name, "uid": rule.uid}


def _position_payload(hint: dict):
    """Internal hint -> the web_api add-access-rule 'position' value."""
    if hint.get("above"):
        return {"above": hint["above"]}   # VERIFY (accepts rule name / uid / number)
    if hint.get("below"):
        return {"below": hint["below"]}   # VERIFY
    return "bottom"                       # no explicit cleanup -> bottom (above the implicit drop)


def _position_human(hint: Optional[dict], rules: list[ParsedRule]) -> str:
    hint = hint or {}
    if hint.get("_above_cleanup") or (not hint.get("above") and not hint.get("below")):
        return "bottom (above the implicit cleanup)"
    by_uid = {r.uid: r for r in rules}
    if hint.get("above"):
        r = by_uid.get(hint["above"])
        return f"above rule {r.number} ({r.name})" if r else "above the cleanup / blocking rule"
    r = by_uid.get(hint["below"])
    return f"below rule {r.number} ({r.name})" if r else "below the more-specific rule"


def build_preview(session, decision: Decision, req: AccessRequest, rules: list[ParsedRule]) -> dict:
    """Read-only: report exactly what execute() would do, without writing anything."""
    out: dict = {"outcome": decision.outcome.value, "reason": decision.reason,
                 "target_rule": _brief(decision.target_rule)}
    if decision.outcome in (Outcome.NO_OP, Outcome.REVIEW):
        return out

    def _obj(cidr):
        ex = lookup_endpoint(session, cidr)
        return {"ip": cidr, "exists": bool(ex),
                "name": ex or _endpoint_name(ipaddress.ip_network(cidr, strict=False))}

    if decision.outcome == Outcome.WIDEN:
        field = decision.widen_field or "source"
        obj = (_svc_object_preview(session, req) if field == "service"
               else _obj(req.src_cidrs[0] if field == "source" else req.dst_cidrs[0]))
        out["widen"] = {"field": field, "object": obj, "via": f"rule {field} cell"}
    elif decision.outcome == Outcome.CREATE:
        out["source"] = _obj(req.src_cidrs[0])
        out["destination"] = _obj(req.dst_cidrs[0])
        out["service"] = _svc_object_preview(session, req)
        out["position"] = _position_human(decision.position, rules)
        if (decision.position or {}).get("_anomaly"):
            out["anomaly"] = True
    return out


def _apply(session, decision: Decision, req: AccessRequest, layer: str,
           rules: list[ParsedRule], ticket_id: str) -> dict:
    out: dict = {"ops": []}

    if decision.outcome == Outcome.WIDEN:
        field = decision.widen_field or "source"
        obj_name = (_resolve_svc_object(session, req) if field == "service"
                    else resolve_endpoint(session, req.src_cidrs[0] if field == "source"
                                          else req.dst_cidrs[0]))
        out.update(widen_field=field, widen_object=obj_name)
        # Add to the rule's CELL, never to a shared group — modifying a group widens EVERY rule that
        # references it. decide() guarantees the other two cells equal the request exactly, so this
        # grants precisely the requested source x destination x service and nothing more.
        session.call("set-access-rule",
                     {"uid": decision.target_rule.uid, "layer": layer, field: {"add": obj_name}})  # VERIFY
        out["ops"].append(f"set-access-rule {decision.target_rule.uid} {field}.add {obj_name}")
        return out

    # CREATE
    src_name = resolve_endpoint(session, req.src_cidrs[0])
    dst_name = resolve_endpoint(session, req.dst_cidrs[0])
    svc_name = _resolve_svc_object(session, req)
    payload = {
        "layer": layer,
        "position": _position_payload(decision.position or {}),
        "name": f"TKT-{ticket_id}" if ticket_id else None,
        "source": src_name,
        "destination": dst_name,
        "service": svc_name,
        "action": "Accept",
        "track": "Log",
        "comments": f"Automated from ticket {ticket_id}".strip(),
    }
    session.call("add-access-rule", {k: v for k, v in payload.items() if v is not None})  # VERIFY
    out.update(source_object=src_name, destination_object=dst_name, service_object=svc_name,
               position=_position_human(decision.position, rules))
    out["ops"].append("add-access-rule")
    return out


# --------------------------------------------------------------------------- #
# Top-level entry points the router / webhook call
# --------------------------------------------------------------------------- #
def preview(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None) -> dict:
    """Read-only: load -> decide -> describe. Returns {ok, outcome, reason, ..., trace}."""
    try:
        with MgmtSession(server, secret) as s:
            rules = load_layer(s, layer, package)
            decision = decide(req, rules)
            return {"ok": True, **build_preview(s, decision, req, rules), "trace": s.trace}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}


def execute(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None,
            ticket_id: str = "", publish: bool = False) -> dict:
    """Load -> decide -> apply in ONE session. ``publish`` commits; otherwise the change is made
    then DISCARDED (validates against the SMS with zero commit). Discards on any error."""
    try:
        with MgmtSession(server, secret) as s:
            rules = load_layer(s, layer, package)
            decision = decide(req, rules)
            base = {"outcome": decision.outcome.value, "reason": decision.reason,
                    "target_rule": _brief(decision.target_rule)}
            if decision.outcome in (Outcome.NO_OP, Outcome.REVIEW):
                return {"ok": True, "applied": False, "published": False, **base, "trace": s.trace}
            try:
                applied = _apply(s, decision, req, layer, rules, ticket_id)
                if publish:
                    s.publish()
                else:
                    s.discard()
            except MgmtError:
                try:
                    s.discard()
                except MgmtError:
                    pass
                raise
            return {"ok": True, "applied": True, "published": publish,
                    "validated": not publish, **base, **applied, "trace": s.trace}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}


# --------------------------------------------------------------------------- #
# Offline smoke test of the pure decision engine (no management server needed)
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    def _host(ip):
        return [(_ip_int(ip), _ip_int(ip))]

    def _net(cidr):
        n = ipaddress.ip_network(cidr)
        return [(int(n.network_address), int(n.broadcast_address))]

    def _tcp(p):
        return ServiceSet(by_proto={"tcp": _ports_to_iv(str(p))})

    web = ParsedRule(uid="r8", number=8, name="web farm", enabled=True, action="Accept",
                     src=_net("10.1.0.0/24"), dst=_host("172.16.5.10"), svc=_tcp(443))
    dns1 = ParsedRule(uid="r3", number=3, name="dns one", enabled=True, action="Accept",
                      src=_host("10.1.2.250"), dst=_host("9.9.9.9"), svc=_tcp(53))
    deny_db = ParsedRule(uid="r9", number=9, name="block db", enabled=True, action="Drop",
                         src=ANY_IP, dst=_host("172.16.5.20"), svc=_tcp(1521))
    cleanup = ParsedRule(uid="rC", number=99, name="Cleanup rule", enabled=True, action="Drop",
                         src=ANY_IP, dst=ANY_IP, svc=ServiceSet(any=True))
    rulebase = [web, dns1, deny_db, cleanup]

    def show(label, req):
        d = decide(req, rulebase)
        print(f"{label:24} -> {d.outcome.value:7} | {d.reason}")

    show("already allowed", AccessRequest(["10.1.0.50/32"], ["172.16.5.10/32"], "tcp", "443"))
    show("widen source", AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"))
    show("widen destination", AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"))
    show("widen service", AccessRequest(["10.1.2.250/32"], ["9.9.9.9/32"], "tcp", "8443"))
    show("over-grant guarded", AccessRequest(["10.1.0.50/32"], ["172.16.9.9/32"], "tcp", "443"))
    show("create (new)", AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"))
    show("explicit deny", AccessRequest(["192.168.9.9/32"], ["172.16.5.20/32"], "tcp", "1521"))
