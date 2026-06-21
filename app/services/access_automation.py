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
    """A service cell as proto -> port intervals (plus an 'Any' flag)."""
    any: bool = False
    by_proto: dict = field(default_factory=dict)
    complex: bool = False  # held a service we could not parse (named, >, < ...)

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


def svc_relation(req: ServiceSet, rule: ServiceSet) -> Relation:
    if not req.overlaps(rule):
        return Relation.DISJOINT
    a, b = rule.covers(req), req.covers(rule)
    if a and b:
        return Relation.EQUAL
    if a:
        return Relation.SUBSET
    if b:
        return Relation.SUPERSET
    return Relation.OVERLAP


# --------------------------------------------------------------------------- #
# Request / rule / decision models
# --------------------------------------------------------------------------- #
@dataclass
class AccessRequest:
    src_cidrs: list[str]      # e.g. ["192.168.9.9/32"]
    dst_cidrs: list[str]
    protocol: str             # "tcp" | "udp"
    ports: str                # "443" or "8000-8100"
    action: str = "Accept"

    def src_iv(self):
        return _cidrs_to_iv(self.src_cidrs)

    def dst_iv(self):
        return _cidrs_to_iv(self.dst_cidrs)

    def svc(self) -> ServiceSet:
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
    widen_group_uid: Optional[str] = None       # preferred widen target


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
        name = (o.get("name") or "").lower()
        if t == "CpmiAnyObject" or name == "any":
            return ServiceSet(any=True)
        if t in ("service-tcp", "service-udp"):
            proto = "tcp" if t.endswith("tcp") else "udp"
            iv = _parse_port(o.get("port", ""))
            if iv is None:
                s.complex = True
                continue
            s.by_proto[proto] = _merge(s.by_proto.get(proto, []) + iv)
        elif t in ("service-group",):
            sub = _parse_svc(o.get("members", []), objdict)
            if sub.any:
                return ServiceSet(any=True)
            for proto, iv in sub.by_proto.items():
                s.by_proto[proto] = _merge(s.by_proto.get(proto, []) + iv)
            s.complex = s.complex or sub.complex
        else:
            s.complex = True
    return s


def _parse_rule(e, objdict: dict) -> ParsedRule:
    src, src_cx, groups = _parse_net(e.get("source", []), objdict)
    dst, dst_cx, _ = _parse_net(e.get("destination", []), objdict)
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
        source_group_uids=groups,
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
    widen_target: Optional[ParsedRule] = None    # first reachable accept matching dst+svc
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
        interferes = not (_provably_disjoint(rel_src, r.src_unknown)
                          or _provably_disjoint(rel_dst, r.dst_unknown)
                          or _provably_disjoint(rel_svc, r.svc_unknown))

        if r.complex and interferes:
            return Decision(
                Outcome.REVIEW,
                f"rule {r.number} ({r.name}) uses negation or an unresolved object "
                f"in the traffic path -- needs human review",
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

        # (2) widen candidate: dst+svc already covered by a reachable ACCEPT, only src missing. Prefer
        # a rule that references a GROUP (cleanest widen -- add the host to the group) over a bare-cell
        # rule, even if the group-backed one appears later in the (still reachable) scan.
        if (r.is_accept and not r.complex and covering_drop is None
                and rel_dst in (Relation.SUBSET, Relation.EQUAL)
                and rel_svc in (Relation.SUBSET, Relation.EQUAL)
                and rel_src in (Relation.DISJOINT, Relation.OVERLAP, Relation.SUPERSET)):
            if widen_target is None or (not widen_target.source_group_uids and r.source_group_uids):
                widen_target = r

        # Placement lower bound: a fully-resolved rule strictly MORE specific than req (don't shadow it).
        if not r.complex and _is_proper_superset(rel_src, rel_dst, rel_svc):
            lower_anchor = r

    if widen_target is not None:
        grp = widen_target.source_group_uids[0] if widen_target.source_group_uids else None
        how = "add source to the group it references" if grp else "add source to the rule"
        return Decision(
            Outcome.WIDEN,
            f"rule {widen_target.number} ({widen_target.name}) already allows dst+svc; {how}",
            target_rule=widen_target, widen_group_uid=grp,
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

    src_ip = req.src_cidrs[0].split("/")[0]
    existing = lookup_host(session, src_ip)
    out["source"] = {"ip": src_ip, "exists": bool(existing),
                     "name": existing or f"h-{src_ip.replace('.', '-')}"}

    if decision.outcome == Outcome.WIDEN:
        out["widen"] = {"group_uid": decision.widen_group_uid,
                        "via": "group object" if decision.widen_group_uid else "rule source cell"}
    elif decision.outcome == Outcome.CREATE:
        dst_ip = req.dst_cidrs[0].split("/")[0]
        d_exist = lookup_host(session, dst_ip)
        out["destination"] = {"ip": dst_ip, "exists": bool(d_exist),
                              "name": d_exist or f"h-{dst_ip.replace('.', '-')}"}
        s_exist = lookup_service(session, req.protocol, req.ports)
        out["service"] = {"exists": bool(s_exist),
                          "name": s_exist or f"{req.protocol.upper()}-{req.ports}"}
        out["position"] = _position_human(decision.position, rules)
        if (decision.position or {}).get("_anomaly"):
            out["anomaly"] = True
    return out


def _apply(session, decision: Decision, req: AccessRequest, layer: str,
           rules: list[ParsedRule], ticket_id: str) -> dict:
    out: dict = {"ops": []}
    src_name = resolve_host(session, req.src_cidrs[0].split("/")[0])
    out["source_object"] = src_name

    if decision.outcome == Outcome.WIDEN:
        if decision.widen_group_uid:
            session.call("set-group",
                         {"uid": decision.widen_group_uid,
                          "members": {"add": src_name}})                       # VERIFY
            out["ops"].append(f"set-group {decision.widen_group_uid} members.add {src_name}")
        else:
            session.call("set-access-rule",
                         {"uid": decision.target_rule.uid, "layer": layer,
                          "source": {"add": src_name}})                        # VERIFY
            out["ops"].append(f"set-access-rule {decision.target_rule.uid} source.add {src_name}")
    else:  # CREATE
        dst_name = resolve_host(session, req.dst_cidrs[0].split("/")[0])
        svc_name = resolve_service(session, req.protocol, req.ports)
        position = _position_payload(decision.position or {})
        payload = {
            "layer": layer,
            "position": position,
            "name": f"TKT-{ticket_id}" if ticket_id else None,
            "source": src_name,
            "destination": dst_name,
            "service": svc_name,
            "action": "Accept",
            "track": "Log",
            "comments": f"Automated from ticket {ticket_id}".strip(),
        }
        session.call("add-access-rule", {k: v for k, v in payload.items() if v is not None})  # VERIFY
        out.update(destination_object=dst_name, service_object=svc_name,
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
                     src=_net("10.1.0.0/24"), dst=_host("172.16.5.10"), svc=_tcp(443),
                     source_group_uids=["grp-web-src"])
    deny_db = ParsedRule(uid="r9", number=9, name="block db", enabled=True, action="Drop",
                         src=ANY_IP, dst=_host("172.16.5.20"), svc=_tcp(1521))
    cleanup = ParsedRule(uid="rC", number=99, name="Cleanup rule", enabled=True, action="Drop",
                         src=ANY_IP, dst=ANY_IP, svc=ServiceSet(any=True))
    rulebase = [web, deny_db, cleanup]

    def show(label, req):
        d = decide(req, rulebase)
        print(f"{label:22} -> {d.outcome.value:7} | {d.reason}")

    show("already allowed", AccessRequest(["10.1.0.50/32"], ["172.16.5.10/32"], "tcp", "443"))
    show("widen (new src)", AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"))
    show("create (new dst)", AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"))
    show("explicit deny -> review", AccessRequest(["192.168.9.9/32"], ["172.16.5.20/32"], "tcp", "1521"))
