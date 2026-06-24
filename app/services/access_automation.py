"""Ticket-driven access automation engine.

Turns an access request (source, destination, service) into the *minimal correct*
change on a Check Point access layer, via the Management web_api. Mirrors the
four-outcome model that FireMon / Tufin Designer / AlgoSec FireFlow converge on,
grounded in the Al-Shaer & Hamed five-relation algebra (IEEE JSAC 2005):

    NO_OP  - the flow is already permitted              -> change nothing
    WIDEN  - a rule already covers dst+svc, src differs -> extend its source
             (prefer a group the rule already references)
    CREATE - nothing permits it (or a deny blocks it)   -> add a least-privilege
             rule; placed ABOVE a blocking deny so the access takes effect, below
             any more-specific rule, else above the cleanup

The engine is built for AUTOMATION: it never hard-stops the flow for a policy
"review". A rule it can't fully resolve (an updatable feed, a negated/unparsable
cell, a conditional or inline-layer rule) is NOTED as a "possible match — review
later" and the walk CONTINUES; the new allow is then placed BELOW that rule so it
can't leap over a possible block. (Outcome.REVIEW survives only as a defensive
signal for an INCOMPLETE request — no concrete service, or an endpoint that names
no object — and for an ambiguous application/service NAME that matches no single
Check Point object, where the caller returns "did you mean …" suggestions.)

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
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger("dcsim.access_automation")

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


# --------------------------------------------------------------------------- #
# Typed (non-IP) source/destination objects
# --------------------------------------------------------------------------- #
# A source/destination cell can hold objects that do NOT live in IPv4/IPv6 space — they match by a
# different identity entirely: a dns-domain matches by FQDN/DNS, an access-role by identity, a
# security-zone by interface, a dynamic-object by gateway-resolved name, an updatable-object by a
# Check Point-curated feed. The engine reasons about these the SAME way svc_relation reasons about
# apps-vs-ports: each kind is its own space, so two different kinds are provably DISJOINT (an IP
# object can never equal a domain object), with a small set of "opaque" cross-kind cases where one
# kind's container could plausibly include another (an updatable feed can contain FQDNs).
#
# CP object type (lower-cased) -> the TypedExtent field that holds its names.
_TYPED_KIND = {
    "dns-domain": "domains",
    "access-role": "roles",
    "dynamic-object": "dynamic",
    "updatable-object": "updatable",
    "security-zone": "zones",
}
# A request's source/destination "kind" -> the TypedExtent field it matches against. "ip" is the
# default (IPv4/IPv6 interval space) and is handled by the existing relation() path, not here.
_KIND_FIELD = {
    "domain": "domains",
    "access-role": "roles",
    "dynamic-object": "dynamic",
    "updatable-object": "updatable",
    "security-zone": "zones",
}
TYPED_KINDS = tuple(_KIND_FIELD)   # the selectable non-IP request kinds, in declaration order


@dataclass
class TypedExtent:
    """The non-IP objects a source/destination cell references, grouped by identity space. Parallel to
    the IPv4/IPv6 interval list — a cell can hold both (e.g. a host AND a dns-domain)."""
    domains: set = field(default_factory=set)     # dns-domain object names, e.g. {".example.com"}
    roles: set = field(default_factory=set)        # access-role names
    dynamic: set = field(default_factory=set)      # dynamic-object names
    updatable: set = field(default_factory=set)    # updatable-object names (CP-curated feeds)
    zones: set = field(default_factory=set)        # security-zone names

    def add(self, kind: str, name: str) -> None:
        getattr(self, kind).add(name)

    def any_members(self) -> bool:
        return bool(self.domains or self.roles or self.dynamic or self.updatable or self.zones)

    def merge(self, o: "TypedExtent") -> None:
        self.domains |= o.domains
        self.roles |= o.roles
        self.dynamic |= o.dynamic
        self.updatable |= o.updatable
        self.zones |= o.zones


def _domain_norm(name: str) -> tuple[str, bool]:
    """Normalize a dns-domain name to ``(base_fqdn, includes_subdomains)``. Check Point writes a leading
    dot (``.example.com``) to mean 'this domain AND every sub-domain'; no dot means the exact FQDN."""
    n = (name or "").strip().lower().rstrip(".")
    sub = n.startswith(".")
    return n.lstrip("."), sub


def _domain_covers(cell_name: str, req_fqdn: str) -> bool:
    """Does a rule cell's dns-domain object grant a requested domain? A sub-domain object (``.x.com``)
    covers the apex and any sub-domain; an exact object (``x.com``) covers only that FQDN. The REQUEST
    also carries sub-domain semantics (a leading-dot value asks for the domain *and* its sub-domains),
    so an EXACT cell can never cover a sub-domain request — only the same exact FQDN."""
    base, sub = _domain_norm(cell_name)
    req, req_sub = _domain_norm(req_fqdn)
    if not base or not req:
        return False
    if req == base:
        return sub or not req_sub      # an exact cell can't cover a "domain + sub-domains" request
    return bool(sub and req.endswith("." + base))


def _domain_equal(cell_name: str, req_fqdn: str) -> bool:
    """The cell's domain object is EXACTLY the requested domain (same FQDN, same sub-domain semantics)."""
    cb, cs = _domain_norm(cell_name)
    rb, rs = _domain_norm(req_fqdn)
    return cb == rb and cs == rs


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


def _typed_other(typed: TypedExtent, keep_field: str) -> bool:
    """True if the cell holds typed objects of a kind OTHER than ``keep_field`` -- so the cell can't be
    EXACTLY EQUAL to a single-kind request."""
    return any(getattr(typed, f) for f in _KIND_FIELD.values() if f != keep_field)


def typed_relation(kind: str, value: str, is_any: bool, has_ip: bool,
                   typed: TypedExtent, cell_complex: bool, negate: bool) -> tuple[Relation, bool]:
    """Relate a TYPED (non-IP) request — a domain / access-role / dynamic-object / updatable-object /
    security-zone identity — to ONE rule source/destination cell.

    Returns ``(relation, unknown)``. ``unknown`` is True when the cell's reach for this kind can't be
    proven (a negated cell, a truly-unresolvable member, or an opaque cross-kind container) -> the rule
    stays in the path and routes to REVIEW, never silently stepped over.

    Each identity kind is its OWN space (mirroring svc_relation's apps-vs-ports disjointness): a domain
    request is provably DISJOINT from a cell holding only IP / role / zone / dynamic objects, EQUAL or
    SUBSET to a cell naming the same (or a parent) domain, and OVERLAP (uncertain) only against an
    opaque container that could itself include the identity (an updatable feed can contain FQDNs)."""
    unknown = bool(cell_complex or negate)
    if is_any:
        return Relation.SUBSET, unknown            # a specific identity is contained by an Any cell
    field = _KIND_FIELD[kind]
    names = getattr(typed, field)
    if kind == "domain":
        if any(_domain_covers(c, value) for c in names):
            exact = any(_domain_equal(c, value) for c in names)
            cell_only = exact and not has_ip and not _typed_other(typed, field) and len(names) == 1
            return (Relation.EQUAL if cell_only else Relation.SUBSET), unknown
        if typed.updatable:                        # an updatable feed could contain this FQDN -> uncertain
            return Relation.OVERLAP, True
        return Relation.DISJOINT, unknown
    # access-role / dynamic-object / updatable-object / security-zone: matched by EXACT object identity.
    if value in names:
        cell_only = not has_ip and not _typed_other(typed, field) and len(names) == 1
        return (Relation.EQUAL if cell_only else Relation.SUBSET), unknown
    return Relation.DISJOINT, unknown


# --------------------------------------------------------------------------- #
# Request / rule / decision models
# --------------------------------------------------------------------------- #
@dataclass
class AccessRequest:
    src_cidrs: list[str]      # e.g. ["192.168.9.9/32"] — used only when src_kind == "ip"
    dst_cidrs: list[str]
    protocol: str = "tcp"     # "tcp" | "udp" (ignored when `application`/`service` is set)
    ports: str = ""           # "443" or "8000-8100" (ignored when `application`/`service` is set)
    application: Optional[str] = None   # an application-site name (e.g. "Facebook") — overrides everything
    service: Optional[str] = None       # a named non-port service (e.g. "echo-request", "GRE") by name
    service_kind: Optional[str] = None  # its protocol family (icmp/icmp6/sctp/other/…) — set by resolve()
    action: str = "Accept"
    # A TYPED (non-IP) source/destination: kind is "ip" (default — reasons over *_cidrs) or one of
    # TYPED_KINDS (domain / access-role / dynamic-object / updatable-object / security-zone), in which
    # case *_value holds the object's identity (a FQDN for domain, the object name otherwise).
    src_kind: str = "ip"
    src_value: str = ""
    dst_kind: str = "ip"
    dst_value: str = ""
    # The request's service EXPANDED to the same ServiceSet shape the rule side uses (a services-group or a
    # tcp/udp/sctp service resolved to its member ports), set by correlation so a group/named-port request
    # compares against rule cells (which dereference groups to ports) instead of reading DISJOINT. None ->
    # fall back to the coarse representation below. (Apply still writes req.service — the group's name.)
    svc_set: Optional[ServiceSet] = None

    def src_iv(self):
        return _cidrs_to_iv(self.src_cidrs)

    def dst_iv(self):
        return _cidrs_to_iv(self.dst_cidrs)

    def svc(self) -> ServiceSet:
        if self.svc_set is not None:
            return self.svc_set         # correlation expanded the named service/group to real ports
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
    # Per-cell "extent unknown" FOR AN IP REQUEST: the cell was negated, held a truly-unresolvable
    # object, OR held a typed (non-IP) object (a domain/role/zone/dynamic/updatable that could resolve
    # to IPs we can't see). Such a cell is never "provably disjoint" for an IP request -> the rule stays
    # in the path. (A TYPED request reasons in its own identity space via src_typed/src_cx/src_negate.)
    src_unknown: bool = False
    dst_unknown: bool = False
    svc_unknown: bool = False
    # The typed (non-IP) objects each cell references + the raw flags a TYPED request reasons over:
    # src_cx/dst_cx = a TRULY-unresolvable member (over-cap wildcard, unenumerable group, malformed,
    # unknown type); src_negate/dst_negate = the cell was negated. (src_unknown folds these + typed +
    # IP-opacity together for the IP path; the typed path uses them separately.)
    src_typed: TypedExtent = field(default_factory=TypedExtent)
    dst_typed: TypedExtent = field(default_factory=TypedExtent)
    src_cx: bool = False
    dst_cx: bool = False
    src_negate: bool = False
    dst_negate: bool = False
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
    dynamic_layer: bool = False                 # the referenced layer is a Dynamic Layer (sk182252) —
                                                # managed out-of-band by other admins -> EXCLUDED from
                                                # decide() entirely (not descended, not flagged)

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
    notes: list = field(default_factory=list)   # advisory "possible match — review later" warnings for
                                                # opaque rules the walk continued PAST (an updatable feed,
                                                # an unresolvable cell): never block the automated flow,
                                                # just flag them. The outcome is still acted on.


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
    """Resolve a source/destination cell to IPv4/IPv6 intervals AND its typed (non-IP) objects.

    -> (ip intervals, complex?, [group uids], approx?, TypedExtent).
    Resolution is by FIELD, not just type, so any object that exposes a concrete IPv4 extent resolves
    (hosts AND infrastructure objects — gateways, clusters, management/checkpoint-hosts, interoperable
    devices — which carry an ``ipv4-address`` but are not type ``host``).
    Wildcard objects expand to their EXACT interval set (capped — a pathological mask stays opaque), and a
    group-with-exclusion resolves to include∖except when both are exact.
    - ``TypedExtent`` = the non-IP objects the cell references, grouped by identity space (dns-domain,
      access-role, dynamic-object, updatable-object, security-zone). These are captured (not lumped into
      ``complex``) so a TYPED request can be reasoned about; an IP request still treats them as opaque
      (see _parse_rule's src_unknown), preserving the never-step-past-unknown-reach invariant.
    - ``complex`` = the cell held something with NO computable extent of ANY known kind (an over-cap
      wildcard, a group-with-exclusion whose 'except' isn't provably exact, an unenumerable group, a
      malformed address, or an object of an unrecognised type) -> the rule's reach is unknown -> REVIEW.
    - ``approx`` = we resolved an object to its main ``ipv4-address`` but its TRUE reach may exceed that
      single IP (a gateway/cluster can be multi-homed). It is an under-approximation, never an over-
      approximation, so it's safe to drop an ACCEPT out of the path; but decide() never treats an approx
      cell as 'provably disjoint', so an overlapping/uncertain DROP stays in the path -> REVIEW (we must
      never under-approximate a deny)."""
    iv, groups, cx, approx, typed = [], [], False, False, TypedExtent()
    for ref in cell or []:
        o = _deref(ref, objdict)
        t = (o.get("type") or "").lower()
        name = (o.get("name") or "").lower()
        raw_name = o.get("name") or ""
        if t == "cpmianyobject" or name == "any":
            return ANY_IP, False, groups, False, typed
        if t == "group":
            groups.append(o.get("uid", ""))
            mem = o.get("members")
            if mem is None:
                # Membership not in the dictionary (a nested group not inlined, a paging/details-level
                # gap, a thin object copy). We CANNOT enumerate the extent, so it is unknown -> REVIEW.
                # An explicitly-empty group (members: []) is different: a real empty set, kept disjoint.
                cx = True
                continue
            sub_iv, sub_cx, _, sub_ap, sub_typed = _parse_net(mem, objdict)
            iv.extend(sub_iv)
            cx = cx or sub_cx
            approx = approx or sub_ap
            typed.merge(sub_typed)
            if mem and not sub_iv and not sub_cx and not sub_typed.any_members():
                cx = True   # a non-empty member list that resolved to nothing (all unresolvable) -> unknown
            continue
        if t == "group-with-exclusion":
            groups.append(o.get("uid", ""))
            inc, exc = o.get("include"), o.get("except")
            if not inc or not exc:
                cx = True                            # can't see both halves -> unknown extent -> REVIEW
                continue
            b_iv, b_cx, _, b_ap, b_typed = _parse_net([inc], objdict)   # the included set
            e_iv, e_cx, _, e_ap, _ = _parse_net([exc], objdict)         # the excluded set
            typed.merge(b_typed)                     # surface typed objects from the included half
            # Subtract EXACTLY only when the excluded set is provably exact: an under-stated 'except'
            # (approx/unknown) would OVER-state include∖except -> over-grant. The base may be approx (an
            # under-approximation stays an under-approximation after subtraction -> safe).
            if b_cx or e_cx or e_ap:
                cx = True
            else:
                iv.extend(_subtract(b_iv, e_iv))
                approx = approx or b_ap
            continue
        # A typed (non-IP) object — a domain / access-role / dynamic-object / updatable-object /
        # security-zone. Capture its name in its identity space rather than discarding it as 'complex'.
        # Most carry no IP extent, so we record and move on; an updatable-object MAY also expose resolved
        # IP ranges, so it falls through to the IP extraction below as well (its IPs are an extra, safe
        # under-approximation, never replacing the feed semantics).
        kind = _TYPED_KIND.get(t)
        if kind:
            typed.add(kind, raw_name or o.get("uid", ""))
            if kind != "updatable":
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
        if not matched and not kind:                 # an unrecognised object type with no computable
            cx = True                                # extent of any known kind -> unknown -> REVIEW
    return _merge(iv), cx, groups, approx, typed


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
    src, src_cx, src_groups, src_ap, src_typed = _parse_net(e.get("source", []), objdict)
    dst, dst_cx, dst_groups, dst_ap, dst_typed = _parse_net(e.get("destination", []), objdict)
    svc = _parse_svc(e.get("service", []), objdict)
    action = e.get("action")
    if isinstance(action, str):
        action = (objdict.get(action) or {}).get("name", action)
    elif isinstance(action, dict):
        action = action.get("name", "")
    src_negate = bool(e.get("source-negate"))
    dst_negate = bool(e.get("destination-negate"))
    # For an IP request a cell's extent is "unknown" if it was negated, held a truly-unresolvable object,
    # OR held a typed (non-IP) object — a domain/role/zone/dynamic/updatable could resolve to IPs we
    # can't see, so an IP request must never step past it (preserves the pre-typed behaviour exactly).
    src_unknown = bool(src_cx or src_negate or src_typed.any_members())
    dst_unknown = bool(dst_cx or dst_negate or dst_typed.any_members())
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
    inline_dynamic = bool((inline_obj or {}).get("dynamic-layer")) if isinstance(inline_obj, dict) else False
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
        src_typed=src_typed, dst_typed=dst_typed,
        src_cx=bool(src_cx), dst_cx=bool(dst_cx), src_negate=src_negate, dst_negate=dst_negate,
        conditional=bool(conditions), conditions=conditions,
        inline_uid=inline_uid, inline_layer_name=inline_name, inline_cleanup=inline_cleanup,
        dynamic_layer=inline_dynamic,
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


_WEB_APP_PORTS = (80, 443)   # where Check Point App Control identifies a web application: HTTP / HTTPS (/QUIC)


def _rule_may_bear_web_app(rule_svc: ServiceSet) -> bool:
    """Could a rule whose service cell resolves to concrete L4 ports carry an App-Control web application
    (Facebook, YouTube, Office365, …)? Those apps are identified over HTTP/HTTPS, so a rule scoped to ports
    that don't include 80/443 — NetBIOS, DHCP/bootp, SSH, SMTP, … — can NEVER match one (provably disjoint).
    Only a rule whose ports cover 80 or 443 (incl. a broad range that does) keeps the app-vs-L4 uncertainty
    the carve-out / removal logic must respect. Checks every protocol leg (tcp 80/443, udp 443 for QUIC)."""
    for ivs in (rule_svc.by_proto or {}).values():
        if any(lo <= p <= hi for lo, hi in ivs for p in _WEB_APP_PORTS):
            return True
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
    # SYMMETRIC case: an APPLICATION request meeting a rule that carries L4 ports — App Control identifies a
    # (web) app over HTTP/HTTPS, so a rule whose ports COULD carry that traffic (cover 80/443, or a broad
    # range that does) might match the app -> indeterminate (a tcp/443 DROP must stay in the path, else a
    # false NO_OP claims the app is allowed when the gateway is dropping it). But a rule scoped to ports that
    # can NEVER carry a web app — NetBIOS, DHCP/bootp, SSH, a "Silent Drop" — is provably disjoint from the
    # app: don't let it falsely block a carve-out (apply) or a removal (REVIEW). This is the screenshot case.
    if req_svc.apps and rule_svc.by_proto and not rule_svc.any:
        return _rule_may_bear_web_app(rule_svc)
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


def _cant_cover_dim(rel: Relation, req_any: bool, cell_any: bool, unresolved: bool) -> bool:
    """PROVE that this rule cell cannot be a superset-or-equal of the request on one dimension — i.e. the
    rule cannot COVER (already permit) the request. Two provable cases:
      * the request is ANY on this dimension but the cell is NOT Any — a specific cell (even an opaque one)
        is a strict subset of Any, so it can never cover an Any request (this is the "rule has a specific
        destination, so it can't allow a request to Any" case);
      * the dimension is fully resolved and the request is broader than / not contained in the cell
        (SUPERSET / OVERLAP / DISJOINT — anything but SUBSET/EQUAL).
    An UNRESOLVED non-Any dimension proves nothing (the cell might contain the request), so returns False."""
    if req_any and not cell_any:
        return True
    if not unresolved:
        return rel in (Relation.SUPERSET, Relation.OVERLAP, Relation.DISJOINT)
    return False


def _dim_relation(kind: str, value: str, req_iv, r: ParsedRule, which: str) -> tuple[Relation, bool, bool]:
    """Relate ONE request dimension (source or destination) to rule ``r``'s cell on that side, dispatching
    on the request's kind. Returns ``(relation, unknown, approx)`` — the same shape for IP and typed
    requests so decide() reasons uniformly.

    - IP request: the established IPv4/IPv6 interval relation; ``unknown``/``approx`` are the cell's
      precomputed IP-path flags (a typed object in the cell already made src_unknown True -> the rule
      stays in the path, exactly as before typing).
    - Typed request (domain / role / zone / dynamic / updatable): reasoned in that identity space via
      typed_relation(); ``approx`` is always False (an identity is exact, not an under-approximation)."""
    cell_ip = r.src if which == "source" else r.dst
    if kind == "ip":
        unknown = r.src_unknown if which == "source" else r.dst_unknown
        approx = r.src_approx if which == "source" else r.dst_approx
        return relation(req_iv, cell_ip), unknown, approx
    typed = r.src_typed if which == "source" else r.dst_typed
    cell_cx = r.src_cx if which == "source" else r.dst_cx
    negate = r.src_negate if which == "source" else r.dst_negate
    is_any = _covers(cell_ip, ANY_IP)
    has_ip = bool(cell_ip) and not is_any
    rel, unknown = typed_relation(kind, value, is_any, has_ip, typed, cell_cx, negate)
    return rel, unknown, False


@dataclass(frozen=True)
class DecideOptions:
    """Admin-tunable decision/placement behaviour (built from Settings by the caller; decide() stays pure).

    These are the knobs that let an operator TUNE the engine from the portal without touching code — every
    judgment call in decide() that has a defensible alternative is one of these. Each default is the
    current, recommended behaviour, so an unset/blank config decides exactly as before. ``_decide_options()``
    builds this from app_settings (the 'Access automation logic' group)."""
    ignore_conditions: bool = False        # treat VPN/time/data/install-on-scoped rules as unconditional
                                           # (a conditional ACCEPT can then cover; a conditional DROP blocks)
    app_carveout: bool = True              # an APPLICATION request blocked by an in-path rule -> CREATE the
                                           # app-Accept ABOVE it (CP carves out just that app); off -> note +
                                           # place below (conservative, but the new rule may be shadowed)
    override_blocking_deny: bool = True    # a resolved covering/partial DENY -> CREATE the allow ABOVE it so
                                           # the access works; off -> note it + place the new rule BELOW
                                           # (never override an admin's deny; may not achieve the request)
    prefer_widen: bool = True              # reuse by widening an existing rule's cell when possible; off ->
                                           # always CREATE a fresh least-privilege rule (never widen)
    emit_notes: bool = True                # attach advisory 'possible match — review later' notes; off ->
                                           # quiet mode (placement safety is unchanged, only the notes drop)


def _widen_above_block(widen_target: ParsedRule, widen_field: str, blocker: ParsedRule) -> "Decision":
    """A WIDEN preferred over creating a NEW rule above an in-path block: ``widen_target`` is a clean
    reachable ACCEPT (EQUAL to the request in two dimensions) that ALREADY sits above ``blocker`` in the
    top-down walk, so extending its third dimension grants the request there by first-match and the block
    is moot — the same effect as a create-above carve-out, with one fewer rule. Only chosen when widening
    is safe (prefer_widen on, a target found, no opaque possible-deny passed, and — for a real deny — the
    operator allows overriding denies)."""
    others = {"source": "destination + service", "destination": "source + service",
              "service": "source + destination"}[widen_field]
    return Decision(
        Outcome.WIDEN,
        f"rule {widen_target.number} ({widen_target.name}) already matches the request's {others} and sits "
        f"above the blocking rule {blocker.number} ({blocker.name}); widening it grants the access there "
        f"(first-match) — no new rule needed",
        target_rule=widen_target, widen_field=widen_field,
    )


def decide(req: AccessRequest, rules: list[ParsedRule], options: "DecideOptions" = None) -> Decision:
    """Pure: pick the minimal correct change for ``req`` against ``rules``.

    Walks the rulebase top-down, honouring Check Point first-match semantics. The result is always an
    actionable outcome — reuse (NO_OP), widen, or CREATE (placed above a blocking deny when needed) — never
    a policy "review" stop; anything it can't fully resolve is NOTED and the walk continues.

    Thin wrapper around ``_decide``: it owns the ``notes`` list (advisory 'possible match — review later'
    warnings the walk raises when it CONTINUES past an opaque rule instead of hard-stopping) and tags
    them onto whatever single outcome the walk returns — so the automated flow is never halted just
    because some rule in the path holds an object we can't fully resolve.
    """
    options = options or DecideOptions()
    notes: list[str] = []
    decision = _decide(req, rules, options, notes)
    # ``emit_notes`` off = quiet mode: drop the advisory notes (placement/uncertain_deny safety is decided
    # inside _decide and is unaffected — only the human-facing advisories are suppressed).
    if options.emit_notes and notes:
        decision.notes = list(notes) + [n for n in (decision.notes or []) if n not in notes]
    return decision


def _decide(req: AccessRequest, rules: list[ParsedRule], options: "DecideOptions", notes: list) -> Decision:
    """The walk itself. Appends advisory warnings to ``notes`` (shared with ``decide``); returns the
    single chosen Decision. Recurses through ``decide`` (the wrapper) for inline layers, so a sub-layer's
    own notes come back tagged and get merged."""
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
            "the request specifies no concrete service, port, or application -- it is incomplete, so "
            "there is nothing to evaluate or create",
        )

    # Guard 3 -- a typed (non-IP) source/destination must name a concrete identity, and an IP source/
    # destination must resolve to a concrete extent. An empty value on either side can't be reasoned
    # about (a typed cell with no name, or an IP cell that resolved to nothing) -> fail loud, not NO_OP.
    for label, kind, value, iv in (("source", req.src_kind, req.src_value, req_src),
                                   ("destination", req.dst_kind, req.dst_value, req_dst)):
        if kind != "ip" and not (value or "").strip():
            return Decision(
                Outcome.REVIEW,
                f"the {label} is typed as a {kind} but names no object -- the request is incomplete, so "
                f"there is nothing to evaluate or create",
            )
        if kind == "ip" and not iv:
            return Decision(
                Outcome.REVIEW,
                f"the {label} resolves to no concrete IP extent -- the request is incomplete, so there "
                f"is nothing to evaluate or create",
            )

    covering_drop: Optional[ParsedRule] = None   # the catch-all cleanup that floors placement
    widen_target: Optional[ParsedRule] = None    # reachable accept EQUAL in 2 dims, differing in the 3rd
    widen_field: Optional[str] = None            # the dimension to extend: source | destination | service
    lower_anchor: Optional[ParsedRule] = None     # last rule strictly more specific than req
    conditional_skip: Optional[ParsedRule] = None  # a conditional ACCEPT we skipped (for the CREATE note)
    last_enabled = max((i for i, r in enumerate(rules) if r.enabled), default=-1)

    # ``uncertain_deny`` records that the walk continued past an opaque rule that COULD block (a drop /
    # divert). It only constrains PLACEMENT: a new allow must never be inserted ABOVE such a rule (first-
    # match would let it leap over a possible block) -> we force bottom placement when it's set. (The
    # advisory text lives in ``notes``, which the decide() wrapper tags onto the returned outcome.)
    uncertain_deny = False

    for i, r in enumerate(rules):
        if not r.enabled:
            continue

        # Relate each dimension to the rule cell, dispatching on the request's kind (IP vs typed). The
        # effective *_unknown / *_approx come back per-request so the rest of decide() reads uniformly;
        # complex_eff is this rule's "extent unknown for THIS request" (replaces the IP-only r.complex).
        rel_src, src_unknown, src_approx = _dim_relation(req.src_kind, req.src_value, req_src, r, "source")
        rel_dst, dst_unknown, dst_approx = _dim_relation(req.dst_kind, req.dst_value, req_dst, r, "destination")
        rel_svc = svc_relation(req_svc, r.svc)
        # The rule's "extent unknown for THIS request" (replaces the IP-only r.complex). For a fully-IP
        # request this equals the stored r.complex (so the never-reason-past-an-unresolved-rule safety
        # net is unchanged); a TYPED request instead trusts the per-dimension unknowns, so a cell whose
        # only "complexity" was a typed object of the matching kind is now reasoned about, not REVIEW'd.
        all_ip = req.src_kind == "ip" and req.dst_kind == "ip"
        complex_eff = bool(src_unknown or dst_unknown or r.svc_unknown or (all_ip and r.complex))

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
        interferes = not (_provably_disjoint(rel_src, src_unknown or src_approx)
                          or _provably_disjoint(rel_dst, dst_unknown or dst_approx)
                          or _provably_disjoint(rel_svc, r.svc_unknown or svc_indeterminate))

        # A Dynamic Layer (sk182252) is managed OUT-OF-BAND by other admins -> EXCLUDED from our logic: we
        # never descend into it, reason about its sub-rules, or flag it (no note — the user asked for it to
        # be out of the picture). BUT safety still binds: if its parent columns INTERFERE with the request,
        # the rule diverts that traffic into the out-of-band layer, so we must NOT place the new allow
        # ABOVE it (first-match would bypass the out-of-band segmentation). It therefore still acts as a
        # silent placement FLOOR (uncertain_deny -> WIDEN suppressed + bottom placement, guaranteed below
        # the divert). A provably-disjoint dynamic rule can't affect the request -> skipped entirely.
        if r.dynamic_layer:
            if interferes:
                uncertain_deny = True
            continue

        # L7 (application) CARVE-OUT — the precise way to ACHIEVE an application allow-request that an
        # in-path rule would block. Per CP column-based matching, a broad L4 (port) DROP, or an opaque
        # app-category/group DROP, that lies in the request's path matches on the SYN and DROPS the app
        # today; a Facebook-Accept placed BELOW it is shadowed (a dead rule). Creating the app-Accept
        # ABOVE the blocking rule is correct AND safe: CP holds the connection, identifies the app and
        # accepts it, while every OTHER connection on that scope still falls through to the rule — a single
        # application carved out, never an over-grant. (Tunable: app_carveout off -> fall through to the
        # conservative note + place-below path instead.) Only a real application request qualifies; a port
        # request above a port-drop would grant the whole port -> not a carve-out, so it is excluded.
        if (req_svc.apps and r.is_drop and interferes
                and covering_drop is None and not (_is_catchall(r) and i == last_enabled)):
            if options.app_carveout:
                # Prefer WIDENING a clean accept candidate already found ABOVE this drop over a new carve-out
                # rule — the widened rule sits above the drop, so first-match grants the app and the drop is
                # moot (same effect, one fewer rule). Safe: target above, no opaque possible-deny passed.
                # GATED BY app_carveout: when carve-out is OFF the operator wants NO grant above the drop, so
                # we must NOT widen (that would put the grant above it = override) — fall through to place-below.
                if options.prefer_widen and widen_target is not None and not uncertain_deny:
                    return _widen_above_block(widen_target, widen_field, r)
                return Decision(
                    Outcome.CREATE,
                    f"rule {r.number} ({r.name}) may block the requested application; creating the allow "
                    f"ABOVE it so Check Point carves out the application (all other traffic still matches "
                    f"that rule)",
                    target_rule=r, position={"above": r.uid},
                )
            # Carve-out OFF: place BELOW + flag, and STOP. We must NOT continue here — per CP this drop
            # matches the app on the blocked port, so letting a lower Accept be read as a NO_OP would be a
            # false "already permitted". The new rule below won't take effect for traffic this rule blocks.
            return Decision(
                Outcome.CREATE,
                f"rule {r.number} ({r.name}) may block the requested application; per policy not carved out "
                f"— the new rule is placed below it and will not take effect for traffic that rule blocks "
                f"(review)",
                target_rule=r, position={"below": r.uid},
            )

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
                # The "Apply Layer" only kicks in under a condition we can't model -> we can't follow that
                # branch. Don't stop: NOTE it and keep walking (a new rule is placed below it, so it can't
                # leap over whatever the inline layer would have done under the condition).
                notes.append(
                    f"rule {r.number} ({r.name}) applies inline layer “{name}” only under "
                    f"{', '.join(r.conditions)} (a dimension the engine doesn't model) — it may divert or "
                    f"block this traffic; the new rule is placed below it. Review it later.")
                uncertain_deny = True
                continue
            if complex_eff or not _is_subset(rel_src, rel_dst, rel_svc):
                # Only PART of the request enters the inline layer; the rest stays in this layer. We can't
                # cleanly reason across the split -> NOTE and keep walking (placement stays below it).
                notes.append(
                    f"the request only partially matches rule {r.number} ({r.name}); its traffic splits "
                    f"across inline layer “{name}” and the parent layer — the new rule is placed below it. "
                    f"Review it later.")
                uncertain_deny = True
                continue
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
                # No explicit rule there covers it and the layer's cleanup is drop OR unknown: either way
                # the safe, actionable move is to CREATE an explicit allow INSIDE the inline layer (above
                # its cleanup). An explicit allow grants the request regardless of what the implicit
                # cleanup would do, so we don't need to resolve the cleanup to act -- no review stop.
                sub.reason = (f"no rule in inline layer “{name}” (applied by rule {r.number}) covers the "
                              f"request; create a least-privilege rule inside it, above its cleanup")
            elif sub.outcome is Outcome.NO_OP:
                sub.reason = f"already permitted inside inline layer “{name}”: {sub.reason}"
            # WIDEN / CREATE land INSIDE the inline layer (keep a deeper layer a nested recursion set).
            if sub.outcome is not Outcome.NO_OP:
                sub.layer = sub.layer or name
            return sub

        if (complex_eff or svc_uncertain or not r.is_resolved_action) and interferes:
            # This rule lies in the path but holds something we can't fully resolve — an updatable feed
            # (which may itself contain the requested object), an unresolvable/negated cell, or a non-
            # Accept/Drop action. We do NOT hard-stop the whole request on it (that would defeat the
            # automated flow); instead we NOTE it as a possible match to review later and CONTINUE the
            # walk. This is SAFE because nothing we go on to do can weaken the firewall: a NO_OP writes
            # nothing, a WIDEN/CREATE never overrides this rule (a new allow is placed BELOW any opaque
            # possible-deny — see uncertain_deny + placement — so first-match keeps that rule's effect).
            # (A *resolved*, provable covering/partial deny is different — it gets an explicit allow created
            # ABOVE it below; this branch is only the UN-resolvable case, which stays below the rule.)
            # If this rule provably CANNOT cover the request (e.g. the request destination is Any but the
            # rule's destination is a specific object, or a resolved dimension shows the request is
            # broader), then an ACCEPT here can't be the rule that "already permits" it — there is nothing
            # to flag, so skip it silently. (A DROP that can't fully cover may still block a SUBSET, so it
            # is still noted + placed-below below; an opaque ACCEPT that COULD cover is still flagged.)
            cant_cover = (
                _cant_cover_dim(rel_src, req.src_kind == "ip" and _covers(req_src, ANY_IP),
                                _covers(r.src, ANY_IP), src_unknown or src_approx)
                or _cant_cover_dim(rel_dst, req.dst_kind == "ip" and _covers(req_dst, ANY_IP),
                                   _covers(r.dst, ANY_IP), dst_unknown or dst_approx)
                or _cant_cover_dim(rel_svc, req_svc.any, r.svc.any, r.svc_unknown or svc_indeterminate))
            if r.is_accept and cant_cover:
                continue

            why = []
            if src_unknown:
                why.append("a negated or unresolvable source")
            if dst_unknown:
                why.append("a negated or unresolvable destination")
            if svc_uncertain or r.svc_unknown:
                why.append("a negated or unresolvable service/application")
            if not r.is_resolved_action:
                why.append(f"a non-Accept/Drop action (“{r.action or 'unknown'}”)")
            detail = "; ".join(why) or "an unresolvable match condition"
            could_block = r.is_drop or not r.is_resolved_action     # might deny/divert -> placement floor
            effect = ("may already permit it" if r.is_accept else
                      ("may block or divert it — the new rule is placed below it, so it can't override it"
                       if could_block else "may also match it"))
            notes.append(f"rule {r.number} ({r.name}) lies in the path with {detail} — it {effect}; "
                         f"review it later.")
            if could_block:
                uncertain_deny = True
            continue

        # A rule whose match ALSO depends on a column the engine doesn't model -- a VPN community/
        # direction, a time window, a content/data type, an install-on gateway subset, or a service-
        # resource -- is not an always-on Accept/Drop. We can't verify the extra condition, so a
        # conditional DENY/divert in the path is NOTED and the walk CONTINUES (don't hard-stop; the new
        # allow is placed below it so it can't leap over a possible block), and a conditional ACCEPT is
        # excluded from NO_OP / reuse / widen (its grant only holds under that condition) and skipped -- a
        # clean rule decides, or we CREATE a precise rule for the requested (unconditional) traffic, noting
        # why the matching-but-conditional rule doesn't grant it.
        if r.conditional and interferes and not options.ignore_conditions:
            if not r.is_accept:
                # A conditional DENY/divert (VPN / time / data / install-on) only blocks under a column we
                # can't model. Don't stop the flow: NOTE it and keep walking. It MIGHT block under its
                # condition, so we treat it as a possible-deny -> the new allow is placed below it (first-
                # match keeps that rule's effect for the traffic it does match).
                notes.append(
                    f"rule {r.number} ({r.name}) lies in the path but its match is restricted by "
                    f"{', '.join(r.conditions)} (a dimension the engine doesn't model) and it denies or "
                    f"diverts the traffic — it may block this under that condition; the new rule is placed "
                    f"below it. Review it later.")
                uncertain_deny = True
                continue
            conditional_skip = r
            continue

        # A DROP that interferes but whose true extent we CANNOT resolve for this request -- an approx
        # infra object (a gateway/cluster/mgmt resolved to its main IP; its real reach may be WIDER) or an
        # indeterminate/opaque service (an app category, service-other, a port we can't pin to the request)
        # -- is a POSSIBLE block we can't prove. We must NOT override it with a create-ABOVE (that could
        # leap over a real deny we simply couldn't see). NOTE it and CONTINUE, forcing the new allow BELOW
        # it (uncertain_deny). Only a FULLY-RESOLVED covering/partial deny is overridden with a create-
        # above (the branches below) -- there we can prove exactly what it blocks, which is the access the
        # caller asked us to make work.
        if r.is_drop and interferes and (svc_indeterminate or src_approx or dst_approx):
            dim = "service" if svc_indeterminate else "source / destination"
            notes.append(f"rule {r.number} ({r.name}) may block this request — its {dim} extent can't be "
                         f"fully resolved, so the new rule is placed below it. Review it later.")
            uncertain_deny = True
            continue

        # Past here, any rule we reuse / widen / anchor on is fully resolved (rules we couldn't resolve
        # were already NOTED and skipped above; complex+provably-disjoint rules are excluded below).
        fully_covers = not complex_eff and _is_subset(rel_src, rel_dst, rel_svc)

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
            elif not options.override_blocking_deny:
                # Tunable: the operator chose NOT to override an admin's deny. Place the new rule BELOW it
                # and STOP (returning here avoids a lower Accept being read as a NO_OP — first-match, the
                # deny wins). The rule won't take effect until the deny is changed; the reason says so.
                return Decision(
                    Outcome.CREATE,
                    f"traffic is denied by rule {r.number} ({r.name}); per policy the deny is NOT "
                    f"overridden — the new rule is placed below it and will not take effect until that rule "
                    f"is changed (review)",
                    target_rule=r, position={"below": r.uid},
                )
            else:
                # Prefer widening a clean accept already above this deny over a new rule (overriding denies
                # is allowed here, and the widened rule sits above the deny -> first-match grants it).
                if options.prefer_widen and widen_target is not None and not uncertain_deny:
                    return _widen_above_block(widen_target, widen_field, r)
                # A *specific* covering deny currently blocks the request. This tool's job is to make the
                # requested access work, so we CREATE the least-privilege allow directly ABOVE that deny
                # (first-match then hits the allow). The reason names the deny so the operator sees exactly
                # what the new rule takes precedence over.
                return Decision(
                    Outcome.CREATE,
                    f"traffic is currently denied by rule {r.number} ({r.name}); creating the allow ABOVE "
                    f"it so the requested access takes effect",
                    target_rule=r, position={"above": r.uid},
                )

        # A reachable DROP that overlaps the request but does NOT fully cover it partially blocks the
        # flow (e.g. a /32 deny inside a /24 request, or an overlapping range). To make the full request
        # work we create the allow ABOVE it. (A fully-covering deny is handled above; the catch-all
        # cleanup is excluded.)
        if (r.is_drop and not complex_eff and covering_drop is None
                and interferes and not fully_covers and not _is_catchall(r)):
            if not options.override_blocking_deny:
                # Tunable: don't override the deny. Place below it — first-match still drops the part this
                # rule covers, and the new rule grants the rest. STOP (return) so a lower Accept isn't read
                # as a NO_OP.
                return Decision(
                    Outcome.CREATE,
                    f"rule {r.number} ({r.name}) partially denies the requested scope; per policy the deny "
                    f"is NOT overridden — the new rule is placed below it (grants only the part the deny "
                    f"doesn't block)",
                    target_rule=r, position={"below": r.uid},
                )
            # Prefer widening a clean accept already above this partial deny over a new rule.
            if options.prefer_widen and widen_target is not None and not uncertain_deny:
                return _widen_above_block(widen_target, widen_field, r)
            # An overlapping deny blocks PART of the requested scope. Create the allow ABOVE it so the full
            # request takes effect (first-match hits the allow before this partial deny).
            return Decision(
                Outcome.CREATE,
                f"rule {r.number} ({r.name}) partially denies the requested scope; creating the allow "
                f"ABOVE it so the requested access takes effect",
                target_rule=r, position={"above": r.uid},
            )

        # (2) widen candidate: a reachable ACCEPT that is EXACTLY EQUAL to the request in two of the
        # three dimensions {source, destination, service} and differs in the third -> add the request's
        # value for that third dimension to the rule's CELL. The other two MUST be equal, not merely a
        # superset: a cell holds a set, and adding a value grants it combined with EVERY member of the
        # other cells. If a rule's source is {win_client, win_server} and only win_server was requested,
        # widening its destination would also grant win_client -> over-grant. Requiring equality (and
        # adding to the cell, never to a shared group) means we grant precisely src x dst x svc.
        if (options.prefer_widen and widen_target is None and r.is_accept and not complex_eff
                and not svc_indeterminate and not r.conditional and covering_drop is None):
            # A non-differing dimension may serve as the "must be EQUAL" guard ONLY if it is a real,
            # exact extent. An approx cell (an infra object resolved to its main IP — true reach may be
            # wider) that reads EQUAL is an UNDER-approximation: widening the third dimension would grant
            # it combined with the cell's unseen extra addresses -> over-grant. Exclude approx from eq so
            # such a rule falls through to CREATE instead of widening.
            eq = {"source": rel_src == Relation.EQUAL and not src_approx,
                  "destination": rel_dst == Relation.EQUAL and not dst_approx,
                  "service": rel_svc == Relation.EQUAL}
            cov = {"source": _dim_covered(rel_src), "destination": _dim_covered(rel_dst),
                   "service": _dim_covered(rel_svc)}
            not_covered = [d for d in ("source", "destination", "service") if not cov[d]]
            if len(not_covered) == 1:
                field = not_covered[0]
                if all(eq[d] for d in ("source", "destination", "service") if d != field):
                    widen_target, widen_field = r, field

        # Placement lower bound: a fully-resolved rule strictly MORE specific than req (don't shadow it).
        if not complex_eff and _is_proper_superset(rel_src, rel_dst, rel_svc):
            lower_anchor = r

    # WIDEN is suppressed once we've passed an opaque possible-deny: widening a rule that sits ABOVE such
    # a deny would pull the request's traffic into it and let it bypass the (possible) block — a first-
    # match under-deny. CREATE below it is the safe alternative (placement is forced to the bottom above).
    if widen_target is not None and not uncertain_deny:
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
    # If an opaque rule that COULD deny was passed over, never anchor the new allow on a more-specific
    # rule above it (that could place the allow ABOVE the possible-deny -> a first-match leap over it).
    # Drop lower_anchor so placement falls to the cleanup floor / bottom — guaranteed below any such rule.
    anchor = None if uncertain_deny else lower_anchor
    return Decision(
        Outcome.CREATE,
        reason,
        target_rule=covering_drop or anchor,
        position=_placement(covering_drop, anchor),
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
# REMOVE-access engine  (the inverse of decide(): revoke a granted access)
# --------------------------------------------------------------------------- #
class RemovalOutcome(str, Enum):
    NO_OP = "no_op"      # the access isn't permitted today -> nothing to remove
    DISABLE = "disable"  # one rule grants EXACTLY this access -> disable that rule (reversible)
    DENY = "deny"        # a BROADER rule grants it -> insert a least-privilege Drop ABOVE that rule
    REVIEW = "review"    # granted via an opaque / inline / conditional / partial / multi-rule path -> don't guess


@dataclass
class RemovalDecision:
    outcome: RemovalOutcome
    reason: str
    target_rule: Optional[ParsedRule] = None
    position: Optional[dict] = None
    notes: list = field(default_factory=list)


def _still_granted_below(req: AccessRequest, req_src, req_dst, req_svc,
                         rules_below: list[ParsedRule], options: "DecideOptions") -> bool:
    """If the first exact-match ACCEPT were disabled, would first-match STILL permit the request? Walks the
    rules BELOW it with the SAME relation logic as decide_removal: an interfering reachable ACCEPT — or any
    rule whose effect we cannot fully resolve (inline / conditional / opaque / non-Accept-Drop) — means the
    flow could survive -> True (so disabling alone is unsafe; the caller uses a Drop-above instead). A
    fully-covering resolved DROP denies it -> False. Reaching the end with neither -> the implicit cleanup
    denies it -> False. Partial drops and provably-disjoint rules are stepped over."""
    for r in rules_below:
        if not r.enabled:
            continue
        rel_src, src_unknown, src_approx = _dim_relation(req.src_kind, req.src_value, req_src, r, "source")
        rel_dst, dst_unknown, dst_approx = _dim_relation(req.dst_kind, req.dst_value, req_dst, r, "destination")
        rel_svc = svc_relation(req_svc, r.svc)
        all_ip = req.src_kind == "ip" and req.dst_kind == "ip"
        complex_eff = bool(src_unknown or dst_unknown or r.svc_unknown or (all_ip and r.complex))
        svc_indeterminate = _svc_indeterminate(req_svc, r.svc)
        if (_provably_disjoint(rel_src, src_unknown or src_approx)
                or _provably_disjoint(rel_dst, dst_unknown or dst_approx)
                or _provably_disjoint(rel_svc, r.svc_unknown or svc_indeterminate)):
            continue                                      # out of this request's path (incl. a disjoint dyn layer)
        # An interfering Dynamic Layer (sk182252, "Apply Layer") is managed out-of-band: its sub-rulebase is
        # invisible to us (inline_rules is None) and MAY grant the flow once the exact ACCEPT above it is
        # disabled. So it can't be proven harmless -> the flow could survive -> force the safe Drop-above.
        if r.dynamic_layer:
            return True
        if (r.inline_rules is not None or (r.conditional and not options.ignore_conditions)
                or complex_eff or svc_indeterminate or not r.is_resolved_action):
            return True                                   # can't prove the flow is denied below -> assume it survives
        if r.is_drop:
            if _is_subset(rel_src, rel_dst, rel_svc):
                return False                              # a covering DROP denies the whole request
            continue                                      # partial drop: the rest may flow on
        return True                                       # a reachable ACCEPT still grants (part of) the request
    return False                                          # nothing below grants it -> implicit cleanup denies it


def decide_removal(req: AccessRequest, rules: list[ParsedRule], options: "DecideOptions" = None) -> RemovalDecision:
    """The INVERSE of decide(): find what GRANTS src->dst:svc and remove it with the least-disruptive SAFE
    move, honouring Check Point first-match. Walk top-down to the FIRST fully-covering, fully-resolved ACCEPT
    (before any covering Drop): grants EXACTLY the request -> DISABLE that rule; grants something BROADER ->
    insert a least-privilege Drop ABOVE it (first-match then denies just this flow; the broad rule still
    serves everyone else, never an over-removal). Already denied / nothing grants it -> NO_OP. An opaque /
    inline / conditional rule in the path, a partial drop, or access granted across multiple rules -> REVIEW
    (removal is destructive — never guess). NARROW (removing a discrete source member) is intentionally NOT
    attempted here: it can't be proven safe from intervals alone (group vs cell member, embedded-in-network),
    so the safe universal primitive is the precise Drop-above."""
    options = options or DecideOptions()
    req_src, req_dst, req_svc = req.src_iv(), req.dst_iv(), req.svc()
    if not req_svc.any and not req_svc.apps and not req_svc.named and not (
            req_svc.by_proto and any(iv for iv in req_svc.by_proto.values())):
        return RemovalDecision(RemovalOutcome.REVIEW, "the request specifies no concrete service, port, or application")
    for label, kind, value, iv in (("source", req.src_kind, req.src_value, req_src),
                                    ("destination", req.dst_kind, req.dst_value, req_dst)):
        if kind != "ip" and not (value or "").strip():
            return RemovalDecision(RemovalOutcome.REVIEW, f"the {label} is typed {kind} but names no object")
        if kind == "ip" and not iv:
            return RemovalDecision(RemovalOutcome.REVIEW, f"the {label} resolves to no concrete IP extent")

    for idx, r in enumerate(rules):
        if not r.enabled:
            continue
        rel_src, src_unknown, src_approx = _dim_relation(req.src_kind, req.src_value, req_src, r, "source")
        rel_dst, dst_unknown, dst_approx = _dim_relation(req.dst_kind, req.dst_value, req_dst, r, "destination")
        rel_svc = svc_relation(req_svc, r.svc)
        all_ip = req.src_kind == "ip" and req.dst_kind == "ip"
        complex_eff = bool(src_unknown or dst_unknown or r.svc_unknown or (all_ip and r.complex))
        svc_indeterminate = _svc_indeterminate(req_svc, r.svc)
        interferes = not (_provably_disjoint(rel_src, src_unknown or src_approx)
                          or _provably_disjoint(rel_dst, dst_unknown or dst_approx)
                          or _provably_disjoint(rel_svc, r.svc_unknown or svc_indeterminate))
        if r.dynamic_layer:
            if interferes:
                return RemovalDecision(RemovalOutcome.REVIEW,
                                       f"rule {r.number} ({r.name}) applies a Dynamic Layer (sk182252) managed "
                                       f"out-of-band — remove this access there, not here")
            continue
        if not interferes:
            continue
        # an unresolved / inline / conditional / opaque rule sits in the path before any clean grant -> a
        # destructive change can't be reasoned past it safely.
        if (r.inline_rules is not None or (r.conditional and not options.ignore_conditions)
                or complex_eff or svc_indeterminate or not r.is_resolved_action):
            return RemovalDecision(RemovalOutcome.REVIEW,
                                   f"rule {r.number} ({r.name}) lies in the path but can't be fully resolved "
                                   f"(inline layer / conditional / opaque cell / non-Accept-Drop action) — "
                                   f"review the removal manually")
        fully_covers = _is_subset(rel_src, rel_dst, rel_svc)
        if r.is_drop:
            if fully_covers:
                return RemovalDecision(RemovalOutcome.NO_OP,
                                       f"already denied by rule {r.number} ({r.name}) — the access is not "
                                       f"permitted; nothing to remove", target_rule=r)
            return RemovalDecision(RemovalOutcome.REVIEW,
                                   f"rule {r.number} ({r.name}) partially denies the request; the removal "
                                   f"interacts with it — review manually", target_rule=r)
        # a reachable ACCEPT
        if fully_covers:
            # DISABLE only when the rule grants EXACTLY this and NOTHING ELSE relies on it. Two proofs are
            # required, both safety-critical: (1) no approx cell — an infra object resolved to its main IP
            # reads EQUAL but its true reach may be WIDER, so disabling the rule would revoke access for
            # those unseen addresses too (over-removal); (2) no rule BELOW re-grants the flow — otherwise
            # first-match would fall through to it and the access would survive (under-removal: we'd report
            # it removed when it isn't). Either proof failing -> the always-safe Drop-above primitive.
            exact = (rel_src == Relation.EQUAL and rel_dst == Relation.EQUAL and rel_svc == Relation.EQUAL
                     and not src_approx and not dst_approx)
            if exact and not _still_granted_below(req, req_src, req_dst, req_svc, rules[idx + 1:], options):
                return RemovalDecision(RemovalOutcome.DISABLE,
                                       f"rule {r.number} ({r.name}) grants EXACTLY this access and no rule "
                                       f"below re-grants it — disable it (reversible; nothing else relies on "
                                       f"this rule)", target_rule=r)
            why = ("grants this access but is broader" if not exact else
                   "grants exactly this access, but a rule below also grants it (disabling alone would not "
                   "remove it)")
            return RemovalDecision(RemovalOutcome.DENY,
                                   f"rule {r.number} ({r.name}) {why}; inserting a least-privilege Drop ABOVE "
                                   f"it removes exactly this request by first-match while the rule still "
                                   f"serves its other traffic", target_rule=r,
                                   position={"above": r.uid})
        # accept overlaps but is narrower than the request -> granted piecemeal across rules
        return RemovalDecision(RemovalOutcome.REVIEW,
                               f"rule {r.number} ({r.name}) grants only part of the requested scope; the access "
                               f"spans multiple rules — review the removal manually")

    return RemovalDecision(RemovalOutcome.NO_OP,
                           "no rule grants this access — it is already not permitted; nothing to remove")


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


def _layer_meta(session, layer_ref: str, *, by: str = "uid") -> tuple[str, bool]:
    """An access layer's ``(implicit-cleanup-action, is-dynamic-layer)``. The cleanup is usually already in
    the rule's object dictionary (no extra call); this is the lookup fallback. ``dynamic-layer`` (sk182252)
    marks a layer managed out-of-band -> the caller EXCLUDES it from the engine entirely."""
    if not layer_ref:
        return "", False
    try:
        r = session.call("show-access-layer", {by: layer_ref})          # VERIFY (accepts name or uid)
        return (r.get("implicit-cleanup-action", "") or "").lower(), bool(r.get("dynamic-layer"))
    except Exception:  # noqa: BLE001 — best-effort; on error we just don't learn the cleanup / dynamic flag
        return "", False


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
        # Learn whether this is a Dynamic Layer (sk182252) via show-access-layer. CRITICAL: the
        # ``dynamic-layer`` flag is returned ONLY by show-access-layer — it is NOT in the object dictionary
        # that show-access-rulebase feeds _parse_rule — so we MUST consult the layer here (the objdict's
        # cleanup is no substitute, and gating this on inline_cleanup-absence would miss a dynamic layer
        # whose cleanup happened to be in the dict). One best-effort call per inline rule; it also fills the
        # cleanup if the object dictionary didn't carry it.
        if not r.dynamic_layer:
            cleanup, dyn = _layer_meta(session, r.inline_uid)
            if cleanup and not r.inline_cleanup:
                r.inline_cleanup = cleanup
            if dyn:
                r.dynamic_layer = True
        # A Dynamic Layer is managed out-of-band by other admins -> EXCLUDE it: never pull or descend, and
        # leave inline_rules None + dynamic_layer set so decide() skips the rule entirely.
        if r.dynamic_layer:
            r.inline_rules = None
            continue
        if r.inline_uid in visited:
            r.inline_rules = []                  # cycle -> treat as an empty inline layer (cleanup decides)
            continue
        try:
            sub = pull(r.inline_layer_name or r.inline_uid)
            _attach_inline_layers(session, sub, package, pull, depth - 1, visited | {r.inline_uid})
            r.inline_rules = sub
        except Exception:  # noqa: BLE001 — leave inline_rules None, never assume a grant
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


# CP object type per typed request kind (for show-objects lookup) + whether it may be CREATED from an
# access request. Identity objects that must be defined elsewhere — an access-role (Identity Awareness),
# a security-zone (gateway topology), a CP-curated updatable-object — are REUSE-ONLY: a clear error if
# missing, never silently fabricated (an empty one would grant nothing and mislead the user).
_TYPED_OBJ = {
    "domain":           {"type": "dns-domain",       "creatable": True},
    "dynamic-object":   {"type": "dynamic-object",   "creatable": True},
    "access-role":      {"type": "access-role",      "creatable": False},
    "security-zone":    {"type": "security-zone",    "creatable": False},
    "updatable-object": {"type": "updatable-object", "creatable": False},
}


def _find_dns_domain(session, value: str) -> tuple[Optional[str], bool]:
    """Look for a dns-domain object matching a domain request -> ``(reusable_name, name_clash)``.

    A CP dns-domain object name ALWAYS starts with a dot for BOTH kinds; ``is-sub-domain`` (a boolean) is
    what distinguishes "the domain + its sub-domains" (a leading-dot request value) from "the exact FQDN".
    So we may reuse an existing object ONLY when its name AND its is-sub-domain flag match the request's
    intent — reusing a sub-domain object for an exact request would silently grant ``*.fqdn`` (over-grant).
    Because names are unique, a same-name object with the OPPOSITE flag is a ``name_clash``: the intended
    object can be neither reused nor created -> resolve() fails loud rather than over/under-granting."""
    want = ("." + value.lstrip(".")).lower()
    req_sub = value.startswith(".")
    found = session.call("show-objects", {"filter": value.lstrip("."), "type": "dns-domain",
                                          "limit": 25})  # VERIFY
    clash = False
    for o in found.get("objects", []):
        if (o.get("name") or "").lower() != want:
            continue
        if bool(o.get("is-sub-domain")) == req_sub:
            return o["name"], False
        clash = True
    return None, clash


def lookup_typed_object(session, kind: str, value: str) -> Optional[str]:
    """Existing object name for a typed (non-IP) request endpoint, or None. A domain matches by its
    canonical dotted name AND its is-sub-domain semantics (see _find_dns_domain); the others by exact name."""
    if kind == "domain":
        name, _ = _find_dns_domain(session, value)
        return name
    found = session.call("show-objects", {"filter": value, "type": _TYPED_OBJ[kind]["type"],
                                          "limit": 25})  # VERIFY
    for o in found.get("objects", []):
        if (o.get("name") or "") == value:
            return o["name"]
    return None


def resolve_typed_object(session, kind: str, value: str) -> str:
    """Reuse-or-create the object for a typed request endpoint. Domains and dynamic-objects are created
    when missing; access-roles / security-zones / updatable-objects are REUSE-ONLY (a clear error if
    absent). A dns-domain is reused only when its is-sub-domain semantics match the request (else a
    same-name/opposite-flag clash is reported, never silently widened to ``*.fqdn``)."""
    if kind == "domain":
        reuse, clash = _find_dns_domain(session, value)
        if reuse:
            return reuse
        name = "." + value.lstrip(".")                 # CP dns-domain names always start with a dot
        req_sub = value.startswith(".")
        if clash:
            raise MgmtError(
                f"a dns-domain object named {name} already exists with the opposite is-sub-domain "
                f"setting; this request needs is-sub-domain={str(req_sub).lower()} — resolve the naming "
                f"conflict on the server first.")
        session.call("add-dns-domain", {"name": name, "is-sub-domain": req_sub})  # VERIFY
        return name
    existing = lookup_typed_object(session, kind, value)
    if existing:
        return existing
    if not _TYPED_OBJ[kind]["creatable"]:
        raise MgmtError(
            f"{kind} '{value}' was not found on this server. It can't be created from an access request — "
            f"define it first (an access-role in Identity Awareness, a security-zone in the gateway "
            f"topology, or an updatable-object from Check Point's repository), then re-run.")
    session.call("add-dynamic-object", {"name": value})  # VERIFY
    return value


def typed_object_preview(session, kind: str, value: str) -> dict:
    """Read-only: the object execute() would place for a typed endpoint + whether it already exists. When
    a REUSE-ONLY object (access-role / security-zone / updatable-object) is missing — it can't be created
    from a request — attach the closest existing objects as ``candidates`` so the form can recommend a
    'did you mean' (a creatable domain/dynamic-object just gets made, so it needs no suggestions)."""
    try:
        ex = lookup_typed_object(session, kind, value)
    except MgmtError:
        ex = None
    creatable = _TYPED_OBJ[kind]["creatable"]
    name = ex or (("." + value.lstrip(".")) if kind == "domain" else value)
    out = {"name": name, "exists": bool(ex), "kind": kind, "creatable": creatable}
    if not ex and not creatable:
        try:
            from . import typed_objects
            out["candidates"] = typed_objects.suggest(session, kind, value)
        except Exception:  # noqa: BLE001 — recommendations are best-effort; never break the preview
            out["candidates"] = []
    return out


def _resolve_endpoint_object(session, req: "AccessRequest", side: str) -> str:
    """Reuse-or-create the object for one request endpoint (source/destination), dispatching on its kind."""
    kind = req.src_kind if side == "source" else req.dst_kind
    if kind == "ip":
        cidrs = req.src_cidrs if side == "source" else req.dst_cidrs
        return resolve_endpoint(session, cidrs[0])
    value = req.src_value if side == "source" else req.dst_value
    return resolve_typed_object(session, kind, value)


def _endpoint_object_preview(session, req: "AccessRequest", side: str) -> dict:
    kind = req.src_kind if side == "source" else req.dst_kind
    if kind == "ip":
        cidr = (req.src_cidrs if side == "source" else req.dst_cidrs)[0]
        ex = lookup_endpoint(session, cidr)
        return {"ip": cidr, "exists": bool(ex),
                "name": ex or _endpoint_name(ipaddress.ip_network(cidr, strict=False))}
    return typed_object_preview(session, kind, req.src_value if side == "source" else req.dst_value)


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
    if decision.notes:                       # advisory 'possible match — review later' warnings
        out["notes"] = list(decision.notes)
    if decision.layer:                       # the change lands inside an inline layer, not the top layer
        out["layer"] = decision.layer
    if decision.outcome in (Outcome.NO_OP, Outcome.REVIEW):
        return out

    if decision.outcome == Outcome.WIDEN:
        field = decision.widen_field or "source"
        obj = (_svc_object_preview(session, req) if field == "service"
               else _endpoint_object_preview(session, req, field))
        out["widen"] = {"field": field, "object": obj, "via": f"rule {field} cell"}
    elif decision.outcome == Outcome.CREATE:
        out["source"] = _endpoint_object_preview(session, req, "source")
        out["destination"] = _endpoint_object_preview(session, req, "destination")
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
    # first CIDR). Fail loud instead — split into one request per CIDR. (Caught as a clean error.) A typed
    # endpoint carries no CIDR (one named object), so the guard only applies to IP endpoints.
    if (req.src_kind == "ip" and len(req.src_cidrs) != 1) or (req.dst_kind == "ip" and len(req.dst_cidrs) != 1):
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
                    else _resolve_endpoint_object(session, req, field))
        out.update(widen_field=field, widen_object=obj_name)
        # Add to the rule's CELL, never to a shared group — modifying a group widens EVERY rule that
        # references it. decide() guarantees the other two cells equal the request exactly, so this
        # grants precisely the requested source x destination x service and nothing more.
        session.call("set-access-rule",
                     {"uid": decision.target_rule.uid, "layer": target_layer,
                      field: {"add": obj_name}})  # VERIFY
        out["ops"].append(f"set-access-rule {decision.target_rule.uid} {field}.add {obj_name}")
        # the exact inverse: drop the object back out of the same cell (rollback/undo).
        out["inverse"] = [{"op": "set-access-rule", "uid": decision.target_rule.uid,
                           "layer": target_layer, "field": field, "remove": obj_name}]
        return out

    # CREATE
    src_name = _resolve_endpoint_object(session, req, "source")
    dst_name = _resolve_endpoint_object(session, req, "destination")
    svc_name = _resolve_svc_object(session, req)
    from . import naming
    # Customer naming/track/tag conventions (Settings → "Access automation"; data-driven templates). The
    # PLACEMENT (position) is NOT a convention — the engine computes it for first-match correctness.
    nctx = {"ticket": (ticket_id or "").strip(), "app": req.application or "",
            "service": req.service or req.application or
                       (f"{(req.protocol or '').lower()}/{req.ports}" if req.ports else ""),
            "source": src_name, "src": src_name, "dest": dst_name, "destination": dst_name,
            "layer": target_layer, "action": "Accept",
            "proto": (req.protocol or "").lower(), "port": req.ports or ""}
    payload = {
        "layer": target_layer,
        "position": _position_payload(decision.position or {}),
        "name": naming.rule_name(ticket_id, nctx),
        "source": src_name,
        "destination": dst_name,
        "service": svc_name,
        "action": "Accept",
        "track": naming.rule_track(),
        "comments": naming.rule_comment(nctx),
    }
    tags = naming.rule_tags()
    if tags:
        payload["tags"] = tags
    created = session.call("add-access-rule", {k: v for k, v in payload.items() if v is not None})  # VERIFY
    created_uid = (created or {}).get("uid")
    out.update(source_object=src_name, destination_object=dst_name, service_object=svc_name,
               position=_position_human(decision.position, _rules_for_layer(decision, rules)),
               created_uid=created_uid)
    out["ops"].append("add-access-rule")
    # the exact inverse: delete the rule we just added (rollback/undo). Reused/created objects are left
    # in place — they may now be referenced elsewhere, and deleting them is a separate, riskier action.
    if created_uid:
        out["inverse"] = [{"op": "delete-access-rule", "uid": created_uid, "layer": target_layer}]
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
        # Expand a services-GROUP or a tcp/udp/sctp service to the SAME ServiceSet the rule side parses
        # (groups dereference to member ports), so the request compares correctly against rule cells.
        # Without this a 'dns' group request read DISJOINT from rule cells holding the same group's ports
        # -> the engine skipped a DNS inline layer and created a shadowed top-level rule. Portless families
        # (icmp/other/rpc/…) keep their named token (the rule side keys them by name too) -> no expansion.
        expanded = _expand_request_service(session, req.service, req.service_kind)
        if expanded is not None:
            req.svc_set = expanded
    return res


def _expand_request_service(session, name: str, kind: str) -> "Optional[ServiceSet]":
    """The request's resolved service as the rule side would parse it. A services-GROUP is dereferenced to
    its members' ports/apps/named; a tcp/udp/sctp service to its port. Returns None for a portless family
    (icmp/other/rpc/gtp/…) — those already match by name — or on any error (best-effort; the coarse named
    fallback is safe: a named-vs-port mismatch reads DISJOINT, never a false grant)."""
    k = (kind or "").lower()
    try:
        if k == "group":
            o = session.call("show-service-group", {"name": name, "details-level": "full"})  # VERIFY
            members = [m for m in (o.get("members") or []) if isinstance(m, dict)]
            sset = _parse_svc(members, {})                       # _deref returns an inline member dict as-is
            guid = o.get("uid")
            if guid and guid not in sset.group_uids:
                sset.group_uids.append(guid)                     # remember the group for widen/reuse
            return sset
        if k in ("tcp", "udp", "sctp"):
            o = session.call(f"show-service-{k}", {"name": name})                              # VERIFY
            return _parse_svc([dict(o, type=f"service-{k}")], {})
    except MgmtError:
        return None
    return None


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


# Behavior PROFILES — one-click bundles of the decision knobs (data, not code; org policy forbids user
# scripting). "balanced" == the recommended defaults; "custom" is NOT here (it falls through to the
# individual toggles). Each must set every DecideOptions field. Surfaced as the `aa_profile` choice Setting.
_PROFILES: dict[str, dict] = {
    # Never touch existing rules and never override a deny: always create a fresh rule, place it BELOW any
    # block (so it may be shadowed) and flag it. The least-disruptive, most hands-off posture.
    "conservative": dict(app_carveout=False, override_blocking_deny=False, prefer_widen=False,
                         emit_notes=True, ignore_conditions=False),
    # The recommended engine defaults: reuse/widen where exact, carve apps + override denies by placement so
    # the access actually works, conditions respected, advisories on.
    "balanced": dict(app_carveout=True, override_blocking_deny=True, prefer_widen=True,
                     emit_notes=True, ignore_conditions=False),
    # Make it work in the fewest rules with the least friction: also treat conditional rules as
    # unconditional and stay quiet (no advisory notes).
    "aggressive": dict(app_carveout=True, override_blocking_deny=True, prefer_widen=True,
                       emit_notes=False, ignore_conditions=True),
    # AUTOPILOT — the lab-demo profile: maximally decisive (like Aggressive) but keeps the advisory notes ON
    # so the agent can NARRATE what it did ("widened rule 2 above the Silent Drop…"). Pair it with the
    # Autopilot agent prompt + MCP publish enabled for the one-sentence-does-everything-and-publishes demo.
    "autopilot": dict(app_carveout=True, override_blocking_deny=True, prefer_widen=True,
                      emit_notes=True, ignore_conditions=True),
}


def _scoped_profile(app_settings, server, layer) -> Optional[str]:
    """A per-scope profile override (Settings → ``aa_scope_overrides``) matching this server/layer, or None.
    Lines are ``scope = profile``; scope = server(name|id) | ``server:layer`` | ``*:layer``. Most-specific
    wins (exact server+layer ▸ ``*:layer`` ▸ server). Only the named profile bundles are honored; blank /
    ``#`` / malformed / unknown-profile lines are ignored (fail safe → falls back to the global profile)."""
    raw = str(app_settings.get("aa_scope_overrides") or "").strip()
    if not raw:
        return None
    sid = str(getattr(server, "id", "") or "").lower()
    sname = (getattr(server, "name", "") or "").strip().lower()
    lname = (layer or "").strip().lower()
    best, best_score = None, -1
    for line in raw.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or "=" not in line:
            continue
        scope, prof = (p.strip() for p in line.split("=", 1))
        prof = prof.lower()
        if prof not in _PROFILES:                      # named bundles only ('custom' isn't a per-scope value)
            continue
        if ":" in scope:
            sp, lp = (p.strip().lower() for p in scope.split(":", 1))
        else:
            sp, lp = scope.strip().lower(), "*"
        srv_ok = sp in ("", "*") or sp == sname or (sid and sp == sid)
        lyr_ok = lp in ("", "*") or lp == lname
        if srv_ok and lyr_ok:
            score = (2 if sp not in ("", "*") else 0) + (1 if lp not in ("", "*") else 0)
            if score > best_score:
                best, best_score = prof, score
    return best


def _decide_options(server=None, layer=None) -> "DecideOptions":
    """Build the engine's decision/placement knobs from the admin's Settings (best-effort). Resolution order:
    a per-scope override (``aa_scope_overrides``) matching this server/layer wins; else the global
    ``aa_profile`` bundle (Conservative/Balanced/Aggressive/Autopilot); else (``custom``/unknown) the
    individual ``aa_*`` toggles. Each Setting/profile carries the same default as DecideOptions, so an
    unconfigured portal decides exactly as before."""
    try:
        from . import app_settings
        profile = _scoped_profile(app_settings, server, layer) or str(app_settings.get("aa_profile") or "custom")
        if profile in _PROFILES:
            return DecideOptions(**_PROFILES[profile])
        return DecideOptions(
            ignore_conditions=bool(app_settings.get("aa_ignore_conditions")),
            app_carveout=bool(app_settings.get("aa_app_carveout")),
            override_blocking_deny=bool(app_settings.get("aa_override_blocking_deny")),
            prefer_widen=bool(app_settings.get("aa_prefer_widen")),
            emit_notes=bool(app_settings.get("aa_emit_notes")),
        )
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


def _dynamic_layer_block(session, layer: str) -> Optional[dict]:
    """If ``layer`` is itself a Dynamic Layer (sk182252) — managed out-of-band by other admins — return a
    refusal dict so the caller stops; otherwise None. Best-effort (a lookup failure just proceeds)."""
    _, dyn = _layer_meta(session, layer, by="name")
    if dyn:
        return {"ok": False, "error": f"“{layer}” is a Dynamic Layer (sk182252) — managed out-of-band by "
                f"another process, so access automation is disabled for it. Choose a standard layer."}
    return None


def preview(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None) -> dict:
    """Read-only: correlate app -> load (cached) -> decide -> describe."""
    try:
        with read_session(server, secret) as s:          # read-only, pooled — no login per preview
            block = _dynamic_layer_block(s, layer)
            if block is not None:                         # the chosen layer is managed out-of-band
                return {**block, "trace": s.trace}
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:
                return _obj_review(res, unresolved, kind, {"cached": False, "trace": s.trace})
            rules, cached = load_layer_cached(s, server, layer, package)
            decision = decide(req, rules, _decide_options(server, layer))
            out = build_preview(s, decision, req, rules)
            return {"ok": True, **out, "cached": cached, "trace": s.trace, **res}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — never let a non-MgmtError (connection/TLS reset, a degraded
        # SDK import leaving read_session=None, an engine bug) propagate to an API/MCP/webhook caller as an
        # opaque "Internal error". Log the stack server-side; hand the caller the real one-line reason.
        logger.exception("access preview failed (layer=%r)", layer)
        return {"ok": False, "error": f"preview failed: {type(exc).__name__}: {exc}"}


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
            block = _dynamic_layer_block(s, layer)
            if block is not None:             # the chosen layer is a Dynamic Layer (managed out-of-band)
                return {**block, "applied": False, "published": False, "trace": s.trace}
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:        # never apply an unresolved / ambiguous application or service
                return {"ok": True, "applied": False, "published": False,
                        **_obj_review(res, unresolved, kind, {"trace": s.trace})}
            rules = load_layer(s, layer, package)
            decision = decide(req, rules, _decide_options(server, layer))
            base = {"outcome": decision.outcome.value, "reason": decision.reason,
                    "target_rule": _brief(decision.target_rule), **res}
            if decision.notes:
                base["notes"] = list(decision.notes)
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
    except Exception as exc:  # noqa: BLE001 — a non-MgmtError before/around the session (unreachable SMS,
        # TLS/cert failure, MgmtSession=None from a degraded import, an engine bug) must come back as a
        # structured error, not an uncaught exception the MCP/webhook layer renders as "Internal error".
        logger.exception("access execute failed (layer=%r, publish=%s)", layer, publish)
        return {"ok": False, "error": f"apply failed: {type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# REMOVE-access I/O  (preview / execute the revoke, mirroring preview()/execute())
# --------------------------------------------------------------------------- #
def _build_removal_preview(decision: RemovalDecision, req: AccessRequest, rules: list[ParsedRule]) -> dict:
    out = {"action": "remove", "outcome": decision.outcome.value, "reason": decision.reason,
           "target_rule": _brief(decision.target_rule)}
    if decision.position:
        out["position"] = _position_human(decision.position, rules)
    if decision.notes:
        out["notes"] = list(decision.notes)
    return out


def _apply_removal(session, decision: RemovalDecision, req: AccessRequest, layer: str, ticket_id: str) -> dict:
    """Materialise a removal: DISABLE = turn the granting rule off; DENY = add a least-privilege Drop ABOVE
    it for exactly src->dst:svc. NO_OP / REVIEW write nothing (handled by the caller)."""
    out: dict = {"ops": []}
    r = decision.target_rule
    if decision.outcome == RemovalOutcome.DISABLE:
        session.call("set-access-rule", {"uid": r.uid, "layer": layer, "enabled": False})  # VERIFY
        out["ops"].append(f"set-access-rule {r.uid} enabled=false")
        out["disabled_uid"] = r.uid
        # the exact inverse: re-enable the rule we disabled (rollback/undo).
        out["inverse"] = [{"op": "set-access-rule", "uid": r.uid, "layer": layer, "enabled": True}]
        return out
    if decision.outcome == RemovalOutcome.DENY:
        src_name = _resolve_endpoint_object(session, req, "source")
        dst_name = _resolve_endpoint_object(session, req, "destination")
        svc_name = _resolve_svc_object(session, req)
        from . import naming
        ctx = {"ticket": (ticket_id or "").strip(), "app": req.application or "",
               "service": req.service or req.application or "", "source": src_name, "dest": dst_name,
               "layer": layer, "action": "Drop"}
        payload = {"layer": layer, "position": _position_payload(decision.position or {}),
                   "name": naming.rule_name(ticket_id, ctx), "source": src_name, "destination": dst_name,
                   "service": svc_name, "action": "Drop", "track": naming.rule_track(),
                   "comments": naming.rule_comment(ctx)}
        tags = naming.rule_tags()
        if tags:
            payload["tags"] = tags
        created = session.call("add-access-rule", {k: v for k, v in payload.items() if v is not None})  # VERIFY
        created_uid = (created or {}).get("uid")
        out.update(source_object=src_name, destination_object=dst_name, service_object=svc_name,
                   created_uid=created_uid)
        out["ops"].append("add-access-rule (Drop)")
        # the exact inverse: delete the Drop we just added (rollback/undo) -> the broad rule grants again.
        if created_uid:
            out["inverse"] = [{"op": "delete-access-rule", "uid": created_uid, "layer": layer}]
        return out
    return out


def remove_preview(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None) -> dict:
    """Read-only: what Drawbridge would do to REVOKE src->dst:svc (no_op / disable / deny / review)."""
    try:
        with read_session(server, secret) as s:
            block = _dynamic_layer_block(s, layer)
            if block is not None:
                return {**block, "trace": s.trace}
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:
                return _obj_review(res, unresolved, kind, {"cached": False, "trace": s.trace})
            rules, cached = load_layer_cached(s, server, layer, package)
            decision = decide_removal(req, rules, _decide_options(server, layer))
            return {"ok": True, **_build_removal_preview(decision, req, rules), "cached": cached,
                    "trace": s.trace, **res}
    except MgmtError as exc:
        return {"ok": False, "error": str(exc)}
    except Exception as exc:  # noqa: BLE001
        logger.exception("removal preview failed (layer=%r)", layer)
        return {"ok": False, "error": f"removal preview failed: {type(exc).__name__}: {exc}"}


def remove_execute(server, secret, req: AccessRequest, layer: str, *, package: Optional[str] = None,
                   ticket_id: str = "", publish: bool = False) -> dict:
    """Load -> decide_removal -> apply the revoke in ONE write session. publish commits; else discard
    (validate with zero commit). NO_OP / REVIEW change nothing. Discards on any error (mirrors execute())."""
    try:
        with MgmtSession(server, secret, session_timeout=write_session_timeout(),
                         session_description="DC-Sim access automation (remove)") as s:
            block = _dynamic_layer_block(s, layer)
            if block is not None:
                return {**block, "applied": False, "published": False, "trace": s.trace}
            res, unresolved, kind = _correlate(s, req)
            if unresolved is not None:
                return {"ok": True, "applied": False, "published": False,
                        **_obj_review(res, unresolved, kind, {"trace": s.trace})}
            rules = load_layer(s, layer, package)
            decision = decide_removal(req, rules, _decide_options(server, layer))
            base = {"action": "remove", "outcome": decision.outcome.value, "reason": decision.reason,
                    "target_rule": _brief(decision.target_rule), **res}
            if decision.notes:
                base["notes"] = list(decision.notes)
            if decision.outcome in (RemovalOutcome.NO_OP, RemovalOutcome.REVIEW):
                return {"ok": True, "applied": False, "published": False, **base, "trace": s.trace}
            try:
                applied = _apply_removal(s, decision, req, layer, ticket_id)
                if publish:
                    s.publish()
                    invalidate_cache(server)
                else:
                    s.discard()
            except Exception as exc:  # noqa: BLE001 — release pending changes + locks on any mid-apply failure
                try:
                    s.discard()
                except MgmtError:
                    sessions = []
                    try:
                        sessions = locking_sessions(server, secret)
                    except Exception:  # noqa: BLE001
                        pass
                    return {"ok": False, "lock_conflict": True, "sessions": sessions, "trace": s.trace,
                            "error": f"the change could not be discarded after a failed removal: {exc}"}
                if isinstance(exc, MgmtError):
                    raise
                return {"ok": False, "error": f"removal failed: {exc}", "trace": s.trace}
            return {"ok": True, "applied": True, "published": publish,
                    "validated": not publish, **base, **applied, "trace": s.trace}
    except MgmtError as exc:
        msg = str(exc)
        out = {"ok": False, "error": msg}
        if _is_lock_error(msg):
            out["lock_conflict"] = True
            out["sessions"] = locking_sessions(server, secret)
        return out
    except Exception as exc:  # noqa: BLE001
        logger.exception("access remove failed (layer=%r, publish=%s)", layer, publish)
        return {"ok": False, "error": f"removal failed: {type(exc).__name__}: {exc}"}


# --------------------------------------------------------------------------- #
# ROLLBACK / undo  (replay an AppliedChange's recorded inverse op-list)
# --------------------------------------------------------------------------- #
_REVERT_FIELDS = {"source", "destination", "service"}


def _apply_inverse_op(session, op: dict) -> str:
    """Translate ONE recorded inverse op (a flat, validated dict) into its web_api call. STRICTLY
    whitelisted — only the three rule edits the engine itself ever emits are accepted (delete a rule,
    re-enable a rule, remove an object from a cell); any other shape is rejected, never executed. The
    op-list comes from our own DB, but validating the shape here keeps a tampered/garbled row from turning
    into an arbitrary management call."""
    kind, uid, layer = op.get("op"), op.get("uid"), op.get("layer")
    if not uid or not layer:
        raise MgmtError(f"malformed rollback op (missing uid/layer): {op!r}")
    if kind == "delete-access-rule":
        session.call("delete-access-rule", {"uid": uid, "layer": layer})  # VERIFY
        return f"delete-access-rule {uid}"
    if kind == "set-access-rule":
        if "enabled" in op:
            session.call("set-access-rule", {"uid": uid, "layer": layer, "enabled": bool(op["enabled"])})  # VERIFY
            return f"set-access-rule {uid} enabled={bool(op['enabled'])}"
        field, obj = op.get("field"), op.get("remove")
        if field in _REVERT_FIELDS and obj:
            session.call("set-access-rule", {"uid": uid, "layer": layer, field: {"remove": obj}})  # VERIFY
            return f"set-access-rule {uid} {field}.remove {obj}"
    raise MgmtError(f"unsupported rollback op: {op!r}")


def _effective_revert_ops(inverse_ops: list[dict], disable_added_rules: bool) -> list[dict]:
    """Resolve the delete-vs-disable choice for an added-rule rollback. Check Point lets a rule be disabled
    rather than deleted, which is the gentler, reversible, auditable undo (the rule stays in the rulebase,
    greyed out, easy to re-enable). When ``disable_added_rules`` is set, every ``delete-access-rule`` op is
    rewritten to disable that rule instead; all other ops (re-enable, remove-from-cell) are unaffected."""
    if not disable_added_rules:
        return inverse_ops
    out = []
    for op in inverse_ops:
        if op.get("op") == "delete-access-rule" and op.get("uid") and op.get("layer"):
            out.append({"op": "set-access-rule", "uid": op["uid"], "layer": op["layer"], "enabled": False})
        else:
            out.append(op)
    return out


def revert_execute(server, secret, inverse_ops: list[dict], *, publish: bool = False,
                   disable_added_rules: bool = False) -> dict:
    """Replay precomputed INVERSE op(s) (from a recorded AppliedChange) in ONE write session to roll back a
    published change — surgically (delete the rule we added / re-enable the rule we disabled / remove the
    object we widened in), never a heavy full-DB revision rollback. ``disable_added_rules`` undoes an
    added-rule change by DISABLING the rule instead of deleting it (reversible, leaves it visible). publish
    commits; otherwise validate then discard (zero commit). Discards on any error (mirrors execute())."""
    if not inverse_ops:
        return {"ok": False, "error": "this change has no recorded inverse — it can't be rolled back here"}
    ops = _effective_revert_ops(inverse_ops, disable_added_rules)
    try:
        with MgmtSession(server, secret, session_timeout=write_session_timeout(),
                         session_description="DC-Sim access automation (revert)") as s:
            ops_done: list[str] = []
            try:
                for op in ops:
                    ops_done.append(_apply_inverse_op(s, op))
                if publish:
                    s.publish()
                    invalidate_cache(server)
                else:
                    s.discard()
            except Exception as exc:  # noqa: BLE001 — release pending changes + locks on any failure
                try:
                    s.discard()
                except MgmtError:
                    sessions = []
                    try:
                        sessions = locking_sessions(server, secret)
                    except Exception:  # noqa: BLE001
                        pass
                    return {"ok": False, "lock_conflict": True, "sessions": sessions, "trace": s.trace,
                            "error": f"the rollback could not be discarded after a failure: {exc}"}
                if isinstance(exc, MgmtError):
                    raise
                return {"ok": False, "error": f"rollback failed: {exc}", "trace": s.trace}
            return {"ok": True, "reverted": publish, "validated": not publish, "ops": ops_done,
                    "mode": "disable" if disable_added_rules else "delete", "trace": s.trace}
    except MgmtError as exc:
        msg = str(exc)
        out = {"ok": False, "error": msg}
        if _is_lock_error(msg):
            out["lock_conflict"] = True
            out["sessions"] = locking_sessions(server, secret)
        return out
    except Exception as exc:  # noqa: BLE001
        logger.exception("access revert failed (publish=%s)", publish)
        return {"ok": False, "error": f"rollback failed: {type(exc).__name__}: {exc}"}


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
