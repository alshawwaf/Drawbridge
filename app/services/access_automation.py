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
R82.10 management server (the SBT lab) before production use. IPv4 + IPv6 are both
modeled (a dual-band integer space, see _V6_BASE); port-based tcp/udp/sctp and
named services are handled, while truly unparsable cells fall through to REVIEW.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

try:  # keep the engine import-safe outside the app runtime (offline smoke test)
    from .mgmt_api import (MgmtError, MgmtSession, _is_lock_error, cached_raw, invalidate_cache,
                           locking_sessions, read_session, write_session_timeout)
except Exception:  # pragma: no cover
    MgmtSession = object  # type: ignore
    read_session = cached_raw = invalidate_cache = locking_sessions = None  # type: ignore
    write_session_timeout = lambda: 300  # type: ignore  # noqa: E731
    _is_lock_error = lambda m: False     # type: ignore  # noqa: E731

    class MgmtError(Exception):
        pass


# IPv4 and IPv6 share ONE integer line, in two non-overlapping BANDS: v4 in [0, 2^32) and v6 mapped to
# [_V6_BASE, _V6_BASE + 2^128). A point/interval lives in exactly one band, so the existing interval math
# (relation/_covers/_overlaps) treats v4 vs v6 as automatically DISJOINT (different bands) while same-
# family ranges compare normally — and "Any" (which in Check Point covers BOTH families) spans both bands.
# This is what lets the engine reason about v6 instead of guarding it out: a v6 request is no longer
# "disjoint from everything" (which used to make the Any/Any cleanup invisible -> silent CREATE).
_V4_MAX = (1 << 32) - 1
# v6 is offset into a band that starts ABOVE a deliberate gap (2^33, not 2^32) so the v4 and v6 bands are
# never ADJACENT — otherwise _merge (which fuses intervals touching at +1) would coalesce an all-v4 +
# all-v6 set into one interval. That fusion is provably lossless (no integer exists between 2^32-1 and
# 2^32), but the gap makes the separation structural so a v4-all + v6-all GROUP stays two intervals that
# mirror ANY_IP exactly, and no future change to _merge can ever leak coverage across the families.
_V6_BASE = 1 << 33
_V6_MAX = (1 << 128) - 1
ANY_IP: list[tuple[int, int]] = [(0, _V4_MAX), (_V6_BASE, _V6_BASE + _V6_MAX)]


def _addr_point(addr: str) -> int:
    """An IP (v4 or v6) -> its point on the shared integer line (v6 offset into its band)."""
    ip = ipaddress.ip_address(addr)
    return int(ip) if ip.version == 4 else _V6_BASE + int(ip)


def _net_interval(net) -> tuple[int, int]:
    """An ip_network (v4 or v6) -> its (lo, hi) interval on the shared line (v6 offset into its band)."""
    base = 0 if net.version == 4 else _V6_BASE
    return (base + int(net.network_address), base + int(net.broadcast_address))


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


def _subtract(base, exclude):
    """Interval-set difference base ∖ exclude (both lists of (lo,hi)). Exact: used to resolve a
    group-with-exclusion (include minus except) to its real extent."""
    result = []
    for lo, hi in _merge(base):
        segs = [(lo, hi)]
        for elo, ehi in _merge(exclude):
            nxt = []
            for slo, shi in segs:
                if ehi < slo or elo > shi:        # no overlap -> keep the segment
                    nxt.append((slo, shi))
                    continue
                if slo < elo:                     # piece left of the exclusion
                    nxt.append((slo, elo - 1))
                if ehi < shi:                     # piece right of the exclusion
                    nxt.append((ehi + 1, shi))
            segs = nxt
        result.extend(segs)
    return _merge(result)


_WILDCARD_CAP = 256        # max intervals a wildcard may expand to before we keep it opaque (REVIEW)


def _wildcard_to_intervals(addr: str, mask: str, base: int, bits: int):
    """Expand a Check Point wildcard (address + WILDCARD mask, where a 1-bit means 'don't care') into the
    EXACT set of (lo,hi) intervals it matches, mapped into the given band. The low contiguous run of
    don't-care bits is one range; each combination of the higher scattered don't-care bits is a separate
    range. Returns None if it would explode past the cap (-> caller keeps it opaque, REVIEW) or on a parse
    error — never an over-approximation."""
    a, m = int(ipaddress.ip_address(addr)), int(ipaddress.ip_address(mask))
    fixed = a & ~m & ((1 << bits) - 1)            # base with every don't-care bit zeroed
    low = 0
    while low < bits and (m >> low) & 1:          # contiguous low don't-care run -> a 2^low block
        low += 1
    block = 1 << low
    scattered = [i for i in range(low, bits) if (m >> i) & 1]
    if len(scattered) > 16 or (1 << len(scattered)) > _WILDCARD_CAP:
        return None                               # too many disjoint ranges -> opaque
    intervals = []
    for combo in range(1 << len(scattered)):
        off = 0
        for j, pos in enumerate(scattered):
            if (combo >> j) & 1:
                off |= (1 << pos)
        intervals.append((base + fixed + off, base + fixed + off + block - 1))
    return _merge(intervals)


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
    named: set = field(default_factory=set)       # non-port service objects by name (icmp, GRE, sctp, …)
    opaque: bool = False                          # an app category/group, or a service whose protocol
                                                  # reach we can't bound vs a port request (other/rpc/gtp…)
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
            exact = rule.apps == req.apps and not rule.by_proto and not rule.named and not rule.opaque
            return Relation.EQUAL if exact else Relation.SUBSET
        return Relation.OVERLAP if rule.opaque else Relation.DISJOINT
    if req.named:                         # NAMED service request (icmp / GRE / sctp / …) — match by name
        if req.named & rule.named:
            exact = (rule.named == req.named and not rule.by_proto and not rule.apps and not rule.opaque)
            return Relation.EQUAL if exact else Relation.SUBSET
        return Relation.OVERLAP if rule.opaque else Relation.DISJOINT
    if not rule.by_proto:                 # PORT request vs a non-port rule. Disjoint UNLESS the rule holds
        return Relation.OVERLAP if rule.opaque else Relation.DISJOINT   # a protocol-ambiguous service.
    a_in_b = _portset_covers(rule.by_proto, req.by_proto)
    b_in_a = _portset_covers(req.by_proto, rule.by_proto)
    # If the rule cell ALSO holds applications / named services / an opaque member, it grants strictly
    # more than the ports, so a pure-port request can never be EXACTLY EQUAL to it -- only a SUBSET (still
    # 'covered', so a genuine no-op stays a no-op). Returning EQUAL would let a widen treat the service as
    # an exact match and drag the rule's extra apps/services onto the new source/destination.
    rule_port_only = not (rule.apps or rule.named or rule.opaque or rule.complex)
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
    protocol: str = "tcp"     # "tcp" | "udp" (ignored when `application`/`service` is set)
    ports: str = ""           # "443" or "8000-8100" (ignored when `application`/`service` is set)
    application: Optional[str] = None   # an application-site name (e.g. "Facebook") — overrides everything
    service: Optional[str] = None       # a named non-port service (e.g. "echo-request", "GRE") by name
    service_kind: Optional[str] = None  # its protocol family (icmp/icmp6/sctp/other/…) — set by resolve()
    action: str = "Accept"

    def src_iv(self):
        return _cidrs_to_iv(self.src_cidrs)

    def dst_iv(self):
        return _cidrs_to_iv(self.dst_cidrs)

    def svc(self) -> ServiceSet:
        if self.application:
            return ServiceSet(apps={self.application})
        if self.service:                # (family, name): family-less (unresolved) fails safe — it won't
            return ServiceSet(named={(self.service_kind or "", self.service)})  # alias a real family object
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
    # An infra object (gateway/cluster/mgmt) resolved to its main ipv4-address — an UNDER-approximation
    # of its possibly-multi-homed reach. Trusted to drop an ACCEPT out of the path; never treated as
    # provably-disjoint, so an overlapping/uncertain DROP with such a cell still routes to REVIEW.
    src_approx: bool = False
    dst_approx: bool = False
    # Match-gating columns the engine does NOT model (VPN community, time window, content/data type,
    # install-on gateway subset, service-resource). When set, the rule only matches UNDER that extra
    # condition -> it is not an always-on Accept/Drop and must never be reused/widened/NO_OP'd.
    conditional: bool = False
    conditions: tuple = ()
    # Inline layer ("Apply Layer"): the parent rule diverts matching traffic into a sub-rulebase. The
    # loader pulls + attaches that rulebase so decide() can recurse purely. inline_rules is None for a
    # normal rule, a (possibly empty) list for an inline-layer rule; inline_cleanup is the inline layer's
    # own implicit cleanup action ("drop" | "accept" | "" unknown) -- what happens when traffic enters
    # the layer but matches no rule there.
    inline_uid: str = ""                        # uid of the referenced inline layer (set by _parse_rule)
    inline_layer_name: str = ""                 # its name (for the apply 'layer' param + messages)
    inline_rules: Optional[list] = None
    inline_cleanup: str = ""

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
    layer: Optional[str] = None                 # target layer for the change — set to an INLINE layer's
                                                # name when the decision lands inside it (else the caller's
                                                # top-level layer is used)


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #
def _ip_int(addr: str) -> int:
    return int(ipaddress.IPv4Address(addr))


def _is_any(cidr) -> bool:
    return str(cidr).strip().lower() == "any"


def _cidrs_to_iv(cidrs):
    iv = []
    for c in cidrs:
        if _is_any(c):
            return ANY_IP
        iv.append(_net_interval(ipaddress.ip_network(c, strict=False)))   # v4 or v6 -> its band
    return _merge(iv)


def _ports_to_iv(spec: str):
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                out.append((int(lo), int(hi)))
            elif part:
                out.append((int(part), int(part)))
        except ValueError:
            continue   # unparsable token -> drop it; an all-empty result hits decide()'s guard 2 -> REVIEW
    return _merge(out)


def _deref(ref, objdict: dict) -> dict:
    """A rule cell holds object UIDs (use-object-dictionary) or inline dicts; resolve to the full obj."""
    if isinstance(ref, str):
        return objdict.get(ref) or {"uid": ref, "name": ref}
    if isinstance(ref, dict):
        return objdict.get(ref.get("uid")) or ref
    return {}


def _parse_net(cell, objdict: dict):
    """Resolve a source/destination cell to IPv4 intervals.

    -> (ip intervals, complex?, [group uids], approx?).
    Resolution is by FIELD, not just type, so any object that exposes a concrete IPv4 extent resolves
    (hosts AND infrastructure objects — gateways, clusters, management/checkpoint-hosts, interoperable
    devices — which carry an ``ipv4-address`` but are not type ``host``).
    Wildcard objects expand to their EXACT interval set (capped — a pathological mask stays opaque), and a
    group-with-exclusion resolves to include∖except when both are exact.
    - ``complex`` = the cell held something with NO computable IPv4 extent (security-zone, dynamic-object,
      updatable-object, access-role, dns-domain, an over-cap wildcard, a group-with-exclusion whose
      'except' isn't provably exact, or a negated cell upstream) -> the rule's reach is unknown -> REVIEW.
    - ``approx`` = we resolved an object to its main ``ipv4-address`` but its TRUE reach may exceed that
      single IP (a gateway/cluster can be multi-homed). It is an under-approximation, never an over-
      approximation, so it's safe to drop an ACCEPT out of the path; but decide() never treats an approx
      cell as 'provably disjoint', so an overlapping/uncertain DROP stays in the path -> REVIEW (we must
      never under-approximate a deny)."""
    iv, groups, cx, approx = [], [], False, False
    for ref in cell or []:
        o = _deref(ref, objdict)
        t = (o.get("type") or "").lower()
        name = (o.get("name") or "").lower()
        if t == "cpmianyobject" or name == "any":
            return ANY_IP, False, groups, False
        if t == "group":
            groups.append(o.get("uid", ""))
            mem = o.get("members")
            if mem is None:
                # Membership not in the dictionary (a nested group not inlined, a paging/details-level
                # gap, a thin object copy). We CANNOT enumerate the extent, so it is unknown -> REVIEW.
                # An explicitly-empty group (members: []) is different: a real empty set, kept disjoint.
                cx = True
                continue
            sub_iv, sub_cx, _, sub_ap = _parse_net(mem, objdict)
            iv.extend(sub_iv)
            cx = cx or sub_cx
            approx = approx or sub_ap
            if mem and not sub_iv and not sub_cx:
                cx = True   # a non-empty member list that resolved to nothing (all unresolvable) -> unknown
            continue
        if t == "group-with-exclusion":
            groups.append(o.get("uid", ""))
            inc, exc = o.get("include"), o.get("except")
            if not inc or not exc:
                cx = True                            # can't see both halves -> unknown extent -> REVIEW
                continue
            b_iv, b_cx, _, b_ap = _parse_net([inc], objdict)   # the included set
            e_iv, e_cx, _, e_ap = _parse_net([exc], objdict)   # the excluded set
            # Subtract EXACTLY only when the excluded set is provably exact: an under-stated 'except'
            # (approx/unknown) would OVER-state include∖except -> over-grant. The base may be approx (an
            # under-approximation stays an under-approximation after subtraction -> safe).
            if b_cx or e_cx or e_ap:
                cx = True
            else:
                iv.extend(_subtract(b_iv, e_iv))
                approx = approx or b_ap
            continue
        # Resolve every IPv4 AND IPv6 extent the object exposes (a dual-stack host carries both) -> each
        # maps to its own band via _net_interval / _addr_point, so v4 and v6 never collide.
        matched = False
        try:
            w4m, w6m = o.get("ipv4-mask-wildcard"), o.get("ipv6-mask-wildcard")
            if w4m or w6m:               # a wildcard object — expand its (non-contiguous) mask EXACTLY, capped
                matched = True           # (wildcard fields are exclusive of subnet/range/host fields)
                for waddr, wmask, base, bits in ((o.get("ipv4-address"), w4m, 0, 32),
                                                 (o.get("ipv6-address"), w6m, _V6_BASE, 128)):
                    if not wmask:
                        continue
                    exp = _wildcard_to_intervals(waddr, wmask, base, bits) if waddr else None
                    if exp is None:
                        cx = True        # no address, or too many disjoint ranges -> keep opaque (REVIEW)
                    else:
                        iv.extend(exp)
            else:
                sub4, ml4 = o.get("subnet4") or o.get("subnet"), o.get("mask-length4", o.get("mask-length"))
                if sub4 and ml4 is not None:         # network (and anything carrying subnet4 + mask)
                    iv.append(_net_interval(ipaddress.ip_network(f"{sub4}/{ml4}", strict=False))); matched = True
                sub6, ml6 = o.get("subnet6"), o.get("mask-length6")
                if sub6 and ml6 is not None:         # IPv6 network
                    iv.append(_net_interval(ipaddress.ip_network(f"{sub6}/{ml6}", strict=False))); matched = True
                f4, l4 = o.get("ipv4-address-first"), o.get("ipv4-address-last")
                if f4 and l4:                        # address-range / multicast-address-range (v4)
                    iv.append((_addr_point(f4), _addr_point(l4))); matched = True
                f6, l6 = o.get("ipv6-address-first"), o.get("ipv6-address-last")
                if f6 and l6:                        # IPv6 address-range
                    iv.append((_addr_point(f6), _addr_point(l6))); matched = True
                a4, a6 = o.get("ipv4-address"), o.get("ipv6-address")
                if a4:                               # host OR an infra object (gateway/cluster/mgmt/...)
                    iv.append((_addr_point(a4), _addr_point(a4))); matched = True
                    if t != "host":                  # main IP only; full reach may be larger -> approx
                        approx = True
                if a6:
                    iv.append((_addr_point(a6), _addr_point(a6))); matched = True
                    if t != "host":
                        approx = True
        except ValueError:
            # A malformed address/subnet in the object dictionary degrades THIS cell to extent-unknown
            # (-> REVIEW) instead of crashing the whole layer pull. Mirrors _ports_to_iv / lookup_host
            # tolerance; fail closed (the rule stays in the path), never silently disjoint.
            cx = matched = True
        if not matched:                              # zone / dynamic / updatable / role / domain / wildcard
            cx = True
    return _merge(iv), cx, groups, approx


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
        if t in ("service-tcp", "service-udp", "service-sctp"):
            # Port-based protocols. SCTP (like TCP/UDP) carries a real destination port, so it is keyed by
            # value in `by_proto` under its OWN protocol -- which never overlaps tcp/udp (distinct keys),
            # so cross-protocol disjointness is automatic while same-protocol port ranges still widen/cover.
            proto = t.replace("service-", "")     # tcp | udp | sctp
            iv = _parse_port(o.get("port", ""))
            if iv is None:
                s.complex = True
            elif (o.get("enable-tcp-resource") or o.get("match-by-protocol-signature")
                  or str(o.get("source-port") or "").strip()):
                # The service matches MORE NARROWLY than its destination port alone -- a URI/CIFS/FTP
                # resource, an L7 protocol signature, or a specific client source-port. Treating it as a
                # plain port would let the engine NO_OP / widen / reuse a rule that does not actually
                # permit all of that port -> silent over-grant. Mark it complex (extent-unknown) so the
                # rule stays in the path and routes to REVIEW instead.
                s.complex = True
            else:
                s.by_proto[proto] = _merge(s.by_proto.get(proto, []) + iv)
        elif t == "application-site":
            s.apps.add(name)
        elif t in ("application-site-category", "application-site-group"):
            s.opaque = True                 # can't enumerate which apps it contains
        elif t in ("service-icmp", "service-icmp6"):
            # PORTLESS protocols (icmp 1 / icmp6 58) matched by type/code, never a port — can NEVER overlap
            # a tcp/udp/sctp port request, so match by name. Key on (family, name): the SAME predefined
            # name exists across families (echo-request is both service-icmp AND service-icmp6) -> no alias.
            s.named.add((t.replace("service-", ""), name))
        elif t in ("service-other", "service-dce-rpc", "service-rpc", "service-gtp",
                   "service-citrix-tcp", "service-compound-tcp"):
            # Match by (family, name), but their protocol/port reach can't be bounded (service-other is
            # an arbitrary IP protocol; rpc/gtp/citrix/compound match dynamically) -> opaque so a PORT
            # request can't assume it's disjoint (stays in the path -> REVIEW for a deny).
            s.named.add((t.replace("service-", ""), name))
            s.opaque = True
        elif t == "service-group":
            s.group_uids.append(o.get("uid", ""))
            mem = o.get("members")
            if mem is None:                     # membership not enumerable -> unknown extent -> REVIEW
                s.complex = True
                continue
            sub = _parse_svc(mem, objdict)
            if sub.any:
                return ServiceSet(any=True)
            for proto, iv in sub.by_proto.items():
                s.by_proto[proto] = _merge(s.by_proto.get(proto, []) + iv)
            s.apps |= sub.apps
            s.named |= sub.named
            s.opaque = s.opaque or sub.opaque
            s.complex = s.complex or sub.complex
        else:
            s.complex = True
    return s


def _cell_is_any(cell, objdict: dict, *defaults: str) -> bool:
    """A match column (vpn/time/content/install-on) imposes NO restriction when it is empty or holds
    ONLY its default object(s) (e.g. 'Any', 'Policy Targets'). Any other named object -- or an unnamed
    structured entry such as a directional-VPN {from,to} pair -- is a real restriction."""
    items = cell or []
    if not items:
        return True
    for ref in items:
        name = (_deref(ref, objdict).get("name") or "").strip().lower()
        if name not in defaults:
            return False
    return True


def _rule_conditions(e: dict, objdict: dict) -> tuple:
    """The match-gating columns the engine does not model. A rule using any of them only matches under
    that extra condition (a VPN community/direction, a time window, a data/content type, a subset of
    gateways, or a service resource) -> it is not an always-on Accept/Drop."""
    conds = []
    if not _cell_is_any(e.get("vpn"), objdict, "any"):
        conds.append("VPN")
    if not _cell_is_any(e.get("time"), objdict, "any"):
        conds.append("time")
    if e.get("content-negate") or not _cell_is_any(e.get("content"), objdict, "any"):
        conds.append("data")
    if not _cell_is_any(e.get("install-on"), objdict, "any", "policy targets"):
        conds.append("install-on")
    if e.get("service-resource"):
        conds.append("service-resource")
    return tuple(conds)


def _parse_rule(e, objdict: dict) -> ParsedRule:
    src, src_cx, src_groups, src_ap = _parse_net(e.get("source", []), objdict)
    dst, dst_cx, dst_groups, dst_ap = _parse_net(e.get("destination", []), objdict)
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
    conditions = _rule_conditions(e, objdict)
    # Inline layer: action "Apply Layer" + an `inline-layer` reference (uid or inline dict). Record the
    # uid + name now; the loader attaches the sub-rulebase. The layer's implicit-cleanup action is read
    # from the object dictionary here when present (no extra call); the loader falls back to a lookup.
    inline_ref = e.get("inline-layer")
    inline_uid = inline_ref if isinstance(inline_ref, str) else (
        (inline_ref or {}).get("uid", "") if isinstance(inline_ref, dict) else "")
    inline_obj = objdict.get(inline_uid) if inline_uid else None
    inline_name = (inline_obj or {}).get("name", "") if isinstance(inline_obj, dict) else ""
    inline_cleanup = ((inline_obj or {}).get("implicit-cleanup-action", "") or "").lower()
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
        src_approx=src_ap, dst_approx=dst_ap,
        conditional=bool(conditions), conditions=conditions,
        inline_uid=inline_uid, inline_layer_name=inline_name, inline_cleanup=inline_cleanup,
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
    if req_svc.named and not (req_svc.named & rule_svc.named):
        return rule_svc.opaque         # a named-service request vs an opaque rule cell -> uncertain
    return False


def _svc_indeterminate(req_svc: ServiceSet, rule_svc: ServiceSet) -> bool:
    """Can we PROVE the service dimension does NOT match? Not when a PORT request meets a rule whose
    service carries an application (concrete or category) that its port leg doesn't already cover --
    App Control identifies L7 over ports, so the rule MIGHT match this port's traffic. Keeping such a
    rule 'in the path' lets a DROP route to REVIEW (don't override a possible block); an ACCEPT is
    harmless to create around. Subsumes the application-request uncertainty (_svc_uncertain)."""
    if _svc_uncertain(req_svc, rule_svc):
        return True
    if (req_svc.by_proto and (rule_svc.apps or rule_svc.opaque)
            and not _portset_covers(rule_svc.by_proto, req_svc.by_proto)):
        return True
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


@dataclass(frozen=True)
class DecideOptions:
    """Admin-tunable automation aggressiveness (built from Settings by the caller; decide() stays pure).
    Both default OFF — the safe, conservative behaviour. Turning one ON converts a class of REVIEW into
    an automatic action because the admin has accepted that risk."""
    override_deny: bool = False        # an explicit (non-cleanup) deny covers/overlaps -> CREATE the
                                       # allow ABOVE it (take precedence) instead of REVIEW
    ignore_conditions: bool = False    # evaluate VPN/time/data/install-on-scoped rules as if uncondi-
                                       # tional (a conditional ACCEPT can cover; a conditional DENY blocks)


def decide(req: AccessRequest, rules: list[ParsedRule], options: "DecideOptions" = None) -> Decision:
    """Pure: pick the minimal correct change for ``req`` against ``rules``.

    Walks the rulebase top-down, honouring Check Point first-match semantics. ``options`` (default: all
    conservative) lets an admin opt into auto-resolving the judgment-call REVIEWs.
    """
    options = options or DecideOptions()
    # IPv6 is now modeled (the dual-band integer space, see _V6_BASE). v4 and v6 occupy disjoint bands and
    # the predefined "Any" spans both, so a v6 request relates correctly to v6 cells, is disjoint from
    # v4-only cells, and is still covered by the Any/Any cleanup -- which is what makes it safe to reason
    # about rather than guard out. (A v4-only "0.0.0.0/0" network object covers only the v4 band, as it
    # should.)
    req_src, req_dst, req_svc = req.src_iv(), req.dst_iv(), req.svc()

    # Guard 2 -- a request that resolves to no concrete service (empty/garbage port, no application) has
    # an empty interval set, which would read as "covered by anything" -> a false NO_OP. Fail loud so the
    # pure surface is self-defending (build_request guards this too, as defense in depth).
    if not req_svc.any and not req_svc.apps and not req_svc.named and not (
            req_svc.by_proto and any(iv for iv in req_svc.by_proto.values())):
        return Decision(
            Outcome.REVIEW,
            "the request specifies no concrete service, port, or application -- cannot reason about "
            "coverage; needs human review",
        )

    covering_drop: Optional[ParsedRule] = None   # the catch-all cleanup that floors placement
    widen_target: Optional[ParsedRule] = None    # reachable accept EQUAL in 2 dims, differing in the 3rd
    widen_field: Optional[str] = None            # the dimension to extend: source | destination | service
    lower_anchor: Optional[ParsedRule] = None     # last rule strictly more specific than req
    conditional_skip: Optional[ParsedRule] = None  # a conditional ACCEPT we skipped (for the CREATE note)
    last_enabled = max((i for i, r in enumerate(rules) if r.enabled), default=-1)

    for i, r in enumerate(rules):
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
        svc_indeterminate = _svc_indeterminate(req_svc, r.svc)
        # An approx cell (infra object resolved to its main IP) is an under-approximation, so it can
        # never be PROVEN disjoint — fold it into the per-cell "unknown". An ACCEPT with an approx cell
        # that doesn't otherwise match simply isn't acted on (harmless); a DROP stays in the path so a
        # possibly-wider deny is never silently stepped over.
        interferes = not (_provably_disjoint(rel_src, r.src_unknown or r.src_approx)
                          or _provably_disjoint(rel_dst, r.dst_unknown or r.dst_approx)
                          or _provably_disjoint(rel_svc, r.svc_unknown or svc_indeterminate))

        # Inline layer ("Apply Layer"): the parent rule's columns gate entry into a sub-rulebase that the
        # loader has attached as r.inline_rules. Honour Check Point first-match: if ALL of the request is
        # contained in the parent's match (and the parent is a plain, unconditional rule), every packet
        # descends into the inline layer and never returns to this layer -> recurse and let the sub-rules
        # plus the inline layer's OWN implicit cleanup decide. If the request only partially matches, it
        # splits across the inline layer and the parent layer (a multi-rule interaction we won't
        # second-guess) -> REVIEW. This converts the old blanket "non-Accept/Drop action" REVIEW into an
        # automatic decision whenever the request lives wholly inside one inline layer.
        if r.inline_rules is not None and interferes and covering_drop is None:
            name = r.inline_layer_name or r.name
            if r.conditional and not options.ignore_conditions:
                return Decision(
                    Outcome.REVIEW,
                    f"rule {r.number} ({r.name}) applies inline layer “{name}” only under "
                    f"{', '.join(r.conditions)} (a dimension the engine doesn't model) -- needs review",
                    target_rule=r,
                )
            if r.complex or not _is_subset(rel_src, rel_dst, rel_svc):
                return Decision(
                    Outcome.REVIEW,
                    f"the request only partially matches rule {r.number} ({r.name}); its traffic splits "
                    f"across inline layer “{name}” and the parent layer -- needs human review",
                    target_rule=r,
                )
            sub = decide(req, r.inline_rules, options)
            if sub.outcome is Outcome.REVIEW:
                return sub
            if sub.outcome is Outcome.CREATE:
                # A CREATE from the recursion is overloaded: it either anchored on an EXPLICIT covering
                # DROP inside the layer (target_rule.is_drop -> a real block, first-match consults it
                # BEFORE the implicit cleanup) or it fell through with no covering rule (target_rule is a
                # non-drop anchor or None -> the implicit cleanup decides). Discriminate, so an explicit
                # bottom Any/Any/Drop in the layer is never silently converted to a NO_OP by an
                # implicit-cleanup=accept (that would step over a covering deny).
                if sub.target_rule is not None and sub.target_rule.is_drop:
                    sub.reason = (f"inline layer “{name}” (rule {r.number}) blocks the request with an "
                                  f"explicit rule {sub.target_rule.number}; create a least-privilege rule "
                                  f"above it, inside the layer")
                    sub.layer = sub.layer or name
                    return sub
                # No explicit rule in the inline layer covers it -> its implicit cleanup is the verdict.
                if r.inline_cleanup == "accept":
                    return Decision(
                        Outcome.NO_OP,
                        f"already permitted by the implicit cleanup (accept) of inline layer “{name}” "
                        f"(applied by rule {r.number})",
                        target_rule=r,
                    )
                if r.inline_cleanup != "drop":
                    return Decision(
                        Outcome.REVIEW,
                        f"the request reaches inline layer “{name}” (rule {r.number}) but no rule there "
                        f"covers it and the layer's implicit cleanup is unknown -- needs human review",
                        target_rule=r,
                    )
                sub.reason = (f"no rule in inline layer “{name}” (applied by rule {r.number}) covers the "
                              f"request; create a least-privilege rule inside it, above its drop cleanup")
            elif sub.outcome is Outcome.NO_OP:
                sub.reason = f"already permitted inside inline layer “{name}”: {sub.reason}"
            # WIDEN / CREATE land INSIDE the inline layer (keep a deeper layer a nested recursion set).
            if sub.outcome is not Outcome.NO_OP:
                sub.layer = sub.layer or name
            return sub

        if (r.complex or svc_uncertain or not r.is_resolved_action) and interferes:
            return Decision(
                Outcome.REVIEW,
                f"rule {r.number} ({r.name}) lies in the traffic path but can't be reasoned about "
                f"(negation, an unresolved object, an application category, or a non-Accept/Drop action "
                f"such as an inline layer) -- needs human review",
                target_rule=r,
            )

        # A rule whose match ALSO depends on a column the engine doesn't model -- a VPN community/
        # direction, a time window, a content/data type, an install-on gateway subset, or a service-
        # resource -- is not an always-on Accept/Drop. We can't verify the extra condition, so a
        # conditional DENY/divert in the path -> REVIEW (don't assume the block is irrelevant), and a
        # conditional ACCEPT is excluded from NO_OP / reuse / widen (its grant only holds under that
        # condition) and skipped -- a clean rule decides, or we CREATE a precise rule for the requested
        # (unconditional) traffic, noting why the matching-but-conditional rule doesn't grant it.
        if r.conditional and interferes and not options.ignore_conditions:
            if not r.is_accept:
                return Decision(
                    Outcome.REVIEW,
                    f"rule {r.number} ({r.name}) lies in the path but its match is restricted by "
                    f"{', '.join(r.conditions)} (a dimension the engine doesn't model) and it denies or "
                    f"diverts the traffic -- can't auto-evaluate; needs human review",
                    target_rule=r,
                )
            conditional_skip = r
            continue

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
            if _is_catchall(r) and i == last_enabled:
                covering_drop = r        # the real bottom cleanup -> placement floor
            elif options.override_deny:
                return Decision(
                    Outcome.CREATE,
                    f"traffic is denied by rule {r.number} ({r.name}); creating the allow ABOVE it "
                    f"(override-deny mode is on)",
                    target_rule=r, position={"above": r.uid},
                )
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
            if options.override_deny:
                return Decision(
                    Outcome.CREATE,
                    f"rule {r.number} ({r.name}) partially denies the requested scope; creating the "
                    f"allow ABOVE it (override-deny mode is on)",
                    target_rule=r, position={"above": r.uid},
                )
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
        if (widen_target is None and r.is_accept and not r.complex and not svc_indeterminate
                and not r.conditional and covering_drop is None):
            # A non-differing dimension may serve as the "must be EQUAL" guard ONLY if it is a real,
            # exact extent. An approx cell (an infra object resolved to its main IP — true reach may be
            # wider) that reads EQUAL is an UNDER-approximation: widening the third dimension would grant
            # it combined with the cell's unseen extra addresses -> over-grant. Exclude approx from eq so
            # such a rule falls through to CREATE/REVIEW instead of widening.
            eq = {"source": rel_src == Relation.EQUAL and not r.src_approx,
                  "destination": rel_dst == Relation.EQUAL and not r.dst_approx,
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

    reason = "no rule covers the request; create a least-privilege rule"
    if conditional_skip is not None:
        reason += (f" (rule {conditional_skip.number} ({conditional_skip.name}) overlaps this request "
                   f"but only applies under {', '.join(conditional_skip.conditions)}, so it does not "
                   f"grant this traffic)")
    return Decision(
        Outcome.CREATE,
        reason,
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
_INLINE_MAX_DEPTH = 4     # inline layers can nest; cap the recursion (a cycle guard backs this up)


def _pull_items(session, layer_name: str, package: Optional[str], max_rules: int = 50000) -> tuple:
    """One layer's raw rulebase items + object dictionary (paged), the pull pattern decide() relies on."""
    items: list[dict] = []
    objdict: dict = {}
    total, offset = 0, 0
    while offset < max_rules:
        payload = {"name": layer_name, "limit": 500, "offset": offset,
                   "use-object-dictionary": True, "details-level": "full",
                   "dereference-group-members": True}   # resolve group cells to member IPs (see decide())
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
    # FAIL LOUD on truncation: a partial rulebase (cleanup + denies past the cap missing) would make
    # decide() under-deny (step over a covering DROP it never loaded). Never decide on a truncated view.
    # Compare total to the CAP, not len(items): `total` is the rule count, `items` is the TOP-LEVEL
    # rulebase (sections wrap rules), so `total > len(items)` falsely tripped on any sectioned layer.
    if total and total > max_rules:
        raise MgmtError(f"access layer “{layer_name}” has {total} rules, over the {max_rules} cap; "
                        f"refusing to decide on a truncated rulebase — raise the cap or split the layer")
    return items, objdict


def _layer_cleanup_action(session, layer_ref: str) -> str:
    """An access layer's implicit cleanup action ("drop" | "accept" | ""). Read straight from the rule's
    object dictionary when present (no extra call); this is the lookup fallback when it wasn't."""
    if not layer_ref:
        return ""
    try:
        r = session.call("show-access-layer", {"uid": layer_ref})       # VERIFY (accepts uid)
        return (r.get("implicit-cleanup-action", "") or "").lower()
    except Exception:  # noqa: BLE001 — best-effort; unknown cleanup just routes the no-match case to REVIEW
        return ""


def _attach_inline_layers(session, rules, package, pull, depth: int, visited: set) -> None:
    """For every "Apply Layer" rule, pull + parse its inline layer's rulebase (recursively) and attach it
    as r.inline_rules so decide() can recurse purely. ``pull(layer_name) -> list[ParsedRule]`` does the
    fetch (fresh or cached). Guards: a depth cap and a visited-uid set (an inline layer referencing one of
    its ancestors would otherwise loop). On any error the rule is left as a normal unresolved action,
    which decide() routes to REVIEW -- never a silent grant."""
    if depth <= 0:
        return
    for r in rules:
        if not r.inline_uid:
            continue
        if r.inline_uid in visited:
            r.inline_rules = []                  # cycle -> treat as an empty inline layer (cleanup decides)
            continue
        try:
            sub = pull(r.inline_layer_name or r.inline_uid)
            _attach_inline_layers(session, sub, package, pull, depth - 1, visited | {r.inline_uid})
            r.inline_rules = sub
            if not r.inline_cleanup:             # not carried in the object dictionary -> look it up once
                r.inline_cleanup = _layer_cleanup_action(session, r.inline_uid)
        except Exception:  # noqa: BLE001 — leave inline_rules None -> REVIEW (safe), never assume a grant
            r.inline_rules = None


def load_layer(session, layer_name: str, package: Optional[str] = None,
               max_rules: int = 50000) -> list[ParsedRule]:
    """Pull a layer with full object details (same pattern as mgmt_api.pull_for_export) and parse
    every rule into value-resolved intervals, attaching any inline-layer sub-rulebases."""
    def _pull(name: str) -> list[ParsedRule]:
        items, objdict = _pull_items(session, name, package, max_rules)
        return [_parse_rule(e, objdict) for e in _flatten(items) if e.get("type") == "access-rule"]

    rules = _pull(layer_name)
    _attach_inline_layers(session, rules, package, _pull, _INLINE_MAX_DEPTH, set())
    return rules


def lookup_host(session, ip: str) -> Optional[str]:
    """Existing host object name for this exact IP (v4 or v6), or None. Read-only (dedup by value;
    compared numerically so a differently-formatted v6 literal still matches)."""
    found = session.call("show-objects",
                         {"filter": ip, "ip-only": True, "type": "host", "limit": 5})  # VERIFY
    try:
        want = ipaddress.ip_address(ip)
    except ValueError:
        want = None
    for o in found.get("objects", []):
        for v in (o.get("ipv4-address"), o.get("ipv6-address")):
            if not v:
                continue
            try:
                if want is not None and ipaddress.ip_address(v) == want:
                    return o["name"]
            except ValueError:
                if v == ip:
                    return o["name"]
    return None


def resolve_host(session, ip: str, name_hint: Optional[str] = None) -> str:
    """Reuse an existing host by exact IP, else create one."""
    existing = lookup_host(session, ip)
    if existing:
        return existing
    from . import naming
    name = name_hint or naming.host_name(ip)
    session.call("add-host", {"name": name, "ip-address": ip})            # VERIFY
    return name


def _endpoint_name(net) -> str:
    from . import naming                       # admin-customisable templates (defaults = the h-/n- scheme)
    addr = str(net.network_address)
    if net.prefixlen == net.max_prefixlen:
        return naming.host_name(addr)
    return naming.network_name(addr, net.prefixlen)


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
    """Existing object for a request endpoint — the predefined Any, a host for /32 & /128, else a
    network — or None."""
    if _is_any(cidr):
        return "Any"
    net = ipaddress.ip_network(cidr, strict=False)
    if net.prefixlen == net.max_prefixlen:
        return lookup_host(session, str(net.network_address))
    return lookup_network(session, net)


def resolve_endpoint(session, cidr: str) -> str:
    """Reuse-or-create the object that represents a request endpoint. Critically, a CIDR wider than a
    single address materializes as a NETWORK object (not a /32 host), so the committed rule covers the
    full requested scope that decide() reasoned over — never silently narrowed to one IP. The literal
    Any references Check Point's predefined Any object and is never created."""
    if _is_any(cidr):
        return "Any"
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
    from . import naming
    name = name_hint or naming.service_name(proto, port)
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
    """The object to put in the rule's 'Services & Applications' cell: an application-site or a named
    service referenced by name (predefined / already correlated to the canonical Check Point name), or
    a reused/created tcp/udp port service."""
    if req.application:
        return req.application
    if req.service:
        return req.service
    return resolve_service(session, req.protocol, req.ports)


def _svc_object_preview(session, req: AccessRequest) -> dict:
    if req.application:
        return {"name": req.application, "exists": lookup_application(session, req.application),
                "kind": "application"}
    if req.service:                       # already correlated to a real service by services.resolve()
        return {"name": req.service, "exists": True, "kind": "service"}
    ex = lookup_service(session, req.protocol, req.ports)
    from . import naming
    return {"name": ex or naming.service_name(req.protocol, req.ports), "exists": bool(ex), "kind": "service"}


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


def _rules_for_layer(decision: Decision, rules: list[ParsedRule]) -> list[ParsedRule]:
    """The rulebase the decision's position uids belong to: when the change lands inside an inline layer
    (decision.layer set), that layer's sub-rules (so the anchor rule renders), else the top-level rules."""
    if decision.layer:
        for r in rules:
            if r.inline_rules is not None and (r.inline_layer_name or r.name) == decision.layer:
                return r.inline_rules
    return rules


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
    if decision.layer:                       # the change lands inside an inline layer, not the top layer
        out["layer"] = decision.layer
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
        out["position"] = _position_human(decision.position, _rules_for_layer(decision, rules))
        if (decision.position or {}).get("_anomaly"):
            out["anomaly"] = True
    return out


def _apply(session, decision: Decision, req: AccessRequest, layer: str,
           rules: list[ParsedRule], ticket_id: str) -> dict:
    out: dict = {"ops": []}
    # decide() reasons over the FULL request (all of src_cidrs/dst_cidrs, merged), but the materialization
    # below writes one object per endpoint. The public build_request() always yields single-element lists;
    # a directly-built multi-CIDR request would otherwise silently apply LESS than was reasoned (only the
    # first CIDR). Fail loud instead — split into one request per CIDR. (Caught as a clean error.)
    if len(req.src_cidrs) != 1 or len(req.dst_cidrs) != 1:
        raise MgmtError("multi-CIDR source/destination is not supported on apply — "
                        "submit one request per source and destination CIDR")
    # The change targets the inline layer when the decision landed inside one (decision.layer); otherwise
    # the caller's top-level layer. The position uids in decision.position belong to that same layer.
    target_layer = decision.layer or layer
    if decision.layer:
        out["layer"] = decision.layer

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
                     {"uid": decision.target_rule.uid, "layer": target_layer,
                      field: {"add": obj_name}})  # VERIFY
        out["ops"].append(f"set-access-rule {decision.target_rule.uid} {field}.add {obj_name}")
        return out

    # CREATE
    src_name = resolve_endpoint(session, req.src_cidrs[0])
    dst_name = resolve_endpoint(session, req.dst_cidrs[0])
    svc_name = _resolve_svc_object(session, req)
    from . import naming
    payload = {
        "layer": target_layer,
        "position": _position_payload(decision.position or {}),
        "name": naming.rule_name(ticket_id),
        "source": src_name,
        "destination": dst_name,
        "service": svc_name,
        "action": "Accept",
        "track": "Log",
        "comments": f"Automated from ticket {ticket_id}".strip(),
    }
    session.call("add-access-rule", {k: v for k, v in payload.items() if v is not None})  # VERIFY
    out.update(source_object=src_name, destination_object=dst_name, service_object=svc_name,
               position=_position_human(decision.position, _rules_for_layer(decision, rules)))
    out["ops"].append("add-access-rule")
    return out


# --------------------------------------------------------------------------- #
# Top-level entry points the router / webhook call
# --------------------------------------------------------------------------- #
def load_layer_cached(session, server, layer: str, package: Optional[str] = None):
    """Parsed rules for ``layer`` via the revision-based policy cache, with inline-layer sub-rulebases
    attached (each pulled through the same cache, keyed by its own name). Returns (rules, cached)."""
    def _pull(name: str) -> list[ParsedRule]:
        raw = cached_raw(session, server, name, package=package)
        return [_parse_rule(e, raw["objdict"]) for e in _flatten(raw["items"])
                if e.get("type") == "access-rule"]

    raw = cached_raw(session, server, layer, package=package)
    rules = [_parse_rule(e, raw["objdict"]) for e in _flatten(raw["items"])
             if e.get("type") == "access-rule"]
    _attach_inline_layers(session, rules, package, _pull, _INLINE_MAX_DEPTH, set())
    return rules, bool(raw.get("cached"))


# --------------------------------------------------------------------------- #
# Read-only policy analysis (the MCP "analyze / insights" tools). PURE over parsed rules.
# --------------------------------------------------------------------------- #
def _svc_definitely_covers(big: ServiceSet, small: ServiceSet) -> bool:
    """Conservative: True only when we can PROVE ``big`` covers ``small`` on the service dimension. Any
    app/named/opaque/complex member on either side -> we don't claim coverage (avoids false shadows)."""
    if big.any:
        return True
    if small.any:
        return False
    if (big.apps or big.named or big.opaque or big.complex
            or small.apps or small.named or small.opaque or small.complex):
        return False
    return _portset_covers(big.by_proto, small.by_proto)


def summarize_rules(rules: list[ParsedRule]) -> dict:
    """High-level shape of a rulebase (for an agent's natural-language overview)."""
    enabled = [r for r in rules if r.enabled]
    def _any(r):  # noqa: ANN001
        return _covers(r.src, ANY_IP), _covers(r.dst, ANY_IP), r.svc.any
    return {
        "total_rules": len(rules),
        "enabled": len(enabled),
        "disabled": sum(1 for r in rules if not r.enabled),
        "accept": sum(1 for r in enabled if r.is_accept),
        "drop_or_reject": sum(1 for r in enabled if r.is_drop),
        "inline_layers": sum(1 for r in enabled if r.inline_rules is not None),
        "conditional": sum(1 for r in enabled if r.conditional),
        "any_source": sum(1 for r in enabled if _any(r)[0]),
        "any_destination": sum(1 for r in enabled if _any(r)[1]),
        "any_service": sum(1 for r in enabled if _any(r)[2]),
        "has_cleanup_drop": any(_is_catchall(r) and r.is_drop for r in enabled),
    }


def find_shadowed(rules: list[ParsedRule]) -> list[dict]:
    """Rules that can NEVER match because an earlier, fully-resolved, unconditional Accept/Drop already
    covers them on all three dimensions (first-match shadowing). Conservative — only provable cases."""
    out: list[dict] = []
    enabled = [r for r in rules if r.enabled]
    for j, rj in enumerate(enabled):
        if rj.complex:
            continue
        for ri in enabled[:j]:
            if ri.complex or ri.conditional or ri.inline_rules is not None or not (ri.is_accept or ri.is_drop):
                continue
            if (relation(rj.src, ri.src) in (Relation.SUBSET, Relation.EQUAL)
                    and relation(rj.dst, ri.dst) in (Relation.SUBSET, Relation.EQUAL)
                    and _svc_definitely_covers(ri.svc, rj.svc)):
                out.append({"rule": rj.number, "name": rj.name, "shadowed_by": ri.number,
                            "shadowed_by_name": ri.name, "covering_action": ri.action})
                break
    return out


def find_permissive(rules: list[ParsedRule]) -> list[dict]:
    """Enabled ACCEPT rules that are broad on a whole dimension (Any source / destination / service) —
    candidates to tighten. The bottom catch-all cleanup (usually a Drop) is naturally excluded."""
    out: list[dict] = []
    for r in rules:
        if not r.enabled or not r.is_accept or r.inline_rules is not None:
            continue
        wide = [d for d, on in (("source", _covers(r.src, ANY_IP)),
                                ("destination", _covers(r.dst, ANY_IP)),
                                ("service", r.svc.any)) if on]
        if wide:
            out.append({"rule": r.number, "name": r.name, "any_dimensions": wide})
    return out


def _resolve_app(session, req: AccessRequest):
    """If the request is application-based, correlate its name to a real Check Point application. On a
    confident (unique exact / normalized-exact) hit, rewrite req.application to CP's canonical name so
    BOTH the rulebase match and any new rule use it. Returns the resolution dict (or None if not an app
    request); the caller turns a no-confident-match into REVIEW with candidates."""
    if not req.application:
        return None
    from . import applications
    res = applications.resolve(session, req.application)
    if res.get("match"):
        req.application = res["match"]
    return res


def _resolve_svc(session, req: AccessRequest):
    """Correlate a named (non-port) service to its canonical Check Point service object. A confident,
    unique match rewrites req.service; otherwise the caller routes to REVIEW with candidates."""
    if not req.service:
        return None
    from . import services
    res = services.resolve(session, req.service)
    if res.get("match"):
        req.service = res["match"]
        req.service_kind = res.get("match_kind") or ""   # tag the family so the engine can't alias it
    return res


def _correlate(session, req: AccessRequest):
    """Resolve the request's application and/or named service to canonical Check Point objects. Returns
    (resolutions, unresolved, kind): ``resolutions`` is the dict to attach to the result; ``unresolved``
    is the resolution that lacked a confident match (-> REVIEW with candidates), or None."""
    res: dict = {}
    app_res = _resolve_app(session, req)
    if app_res is not None:
        res["app_resolution"] = app_res
    svc_res = _resolve_svc(session, req)
    if svc_res is not None:
        res["svc_resolution"] = svc_res
    for r, kind in ((app_res, "application"), (svc_res, "service")):
        if r is not None and not r.get("match"):
            return res, r, kind
    return res, None, ""


def _decide_options() -> "DecideOptions":
    """Build the engine's automation-aggressiveness options from the admin's Settings (best-effort)."""
    try:
        from . import app_settings
        return DecideOptions(override_deny=bool(app_settings.get("aa_override_deny")),
                             ignore_conditions=bool(app_settings.get("aa_ignore_conditions")))
    except Exception:  # noqa: BLE001
        return DecideOptions()


def _obj_review(res: dict, unresolved: dict, kind: str, base: dict) -> dict:
    """An application/service name that didn't resolve to a single Check Point object -> REVIEW, BEFORE any
    write reaches the SMS (so a wrong/typo'd name never produces a failing add-access-rule). The candidate
    matches are surfaced TWO ways: nested (``{kind}_resolution.candidates`` — drives the portal's pick
    chips) AND as a top-level ``suggestions`` list + a 'did you mean …' reason, so a programmatic webhook
    caller gets an actionable correction without digging into the nested dict."""
    names = [c.get("name") for c in (unresolved.get("candidates") or []) if c.get("name")]
    if names:
        hint = f"did you mean: {', '.join(names[:6])}?"
    elif unresolved.get("note"):
        hint = unresolved["note"]
    else:
        hint = f"no close Check Point {kind} matched — check the exact object name"
    return {"ok": True, "outcome": "review", "target_rule": None, "unresolved": kind,
            "reason": f"“{unresolved['term']}” did not match a single Check Point {kind} — {hint}",
            "suggestions": names, **res, **base}


def preview(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None) -> dict:
    """Read-only: correlate app -> load (cached) -> decide -> describe."""
    try:
        with read_session(server, secret) as s:          # read-only, pooled — no login per preview
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:
                return _obj_review(res, unresolved, kind, {"cached": False, "trace": s.trace})
            rules, cached = load_layer_cached(s, server, layer, package)
            decision = decide(req, rules, _decide_options())
            out = build_preview(s, decision, req, rules)
            return {"ok": True, **out, "cached": cached, "trace": s.trace, **res}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}


def execute(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None,
            ticket_id: str = "", publish: bool = False) -> dict:
    """Load -> decide -> apply in ONE session. ``publish`` commits; otherwise the change is made
    then DISCARDED (validates against the SMS with zero commit). Discards on any error."""
    try:
        # WRITE path: an isolated read-write session (NOT the shared read pool) that loads the live
        # policy, decides, applies, and publishes/discards in one transaction -> always decided on
        # fresh rules, locks held only for this commit.
        with MgmtSession(server, secret, session_timeout=write_session_timeout(),
                         session_description="DC-Sim access automation (apply)") as s:
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:        # never apply an unresolved / ambiguous application or service
                return {"ok": True, "applied": False, "published": False,
                        **_obj_review(res, unresolved, kind, {"trace": s.trace})}
            rules = load_layer(s, layer, package)
            decision = decide(req, rules, _decide_options())
            base = {"outcome": decision.outcome.value, "reason": decision.reason,
                    "target_rule": _brief(decision.target_rule), **res}
            if decision.outcome in (Outcome.NO_OP, Outcome.REVIEW):
                return {"ok": True, "applied": False, "published": False, **base, "trace": s.trace}
            try:
                applied = _apply(s, decision, req, layer, rules, ticket_id)
                if publish:
                    s.publish()
                    invalidate_cache(server)   # our change advanced the revision -> drop the read cache
                else:
                    s.discard()
            except Exception as exc:   # noqa: BLE001 — ANY failure mid-apply (incl. a non-MgmtError from
                # resolve_endpoint / naming) must release the write session's pending changes + locks. The
                # session's __exit__ only logs out, and on Check Point a read-WRITE logout does NOT discard
                # — so without this the half-applied object + its locks linger until the session times out.
                try:
                    s.discard()
                except MgmtError:
                    sessions = []
                    try:
                        sessions = locking_sessions(server, secret)
                    except Exception:  # noqa: BLE001
                        pass
                    return {"ok": False, "lock_conflict": True, "sessions": sessions, "trace": s.trace,
                            "error": f"the change could not be discarded after a failed apply: {exc}"}
                if isinstance(exc, MgmtError):
                    raise                      # let the outer handler classify (lock vs generic)
                return {"ok": False, "error": f"apply failed: {exc}", "trace": s.trace}
            return {"ok": True, "applied": True, "published": publish,
                    "validated": not publish, **base, **applied, "trace": s.trace}
    except MgmtError as exc:
        msg = str(exc)
        out = {"ok": False, "error": msg}
        if _is_lock_error(msg):       # name the session holding the lock + let the UI offer a take-over
            out["lock_conflict"] = True
            out["sessions"] = locking_sessions(server, secret)
        return out


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
