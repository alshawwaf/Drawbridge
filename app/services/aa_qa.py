"""Access-automation engine QA — a documented, declarative, RUNNABLE scenario battery.

This is the canonical "test set of change requests covering every supported object / site / port /
protocol / outcome" for the decision engine. Each scenario is data (no test framework): a small
Check-Point-lab-shaped rulebase (objects + rules), one access request, and the Check-Point-correct
expected outcome. Scenarios are parsed through the REAL engine (the same ``_parse_rule`` + ``decide`` /
``decide_removal`` the live ``web_api`` path uses), so they exercise actual object resolution — the layer
where the Internet-object, Dynamic-Layer and disabled-rule bugs hid.

RUN IT
------
  * Standalone (no pytest)::            python -m app.services.aa_qa            # full report, exit 1 on any fail
                                        python -m app.services.aa_qa --category placement
                                        python -m app.services.aa_qa --list     # list scenario ids + descriptions
  * As part of the suite::             pytest tests/test_aa_scenarios.py        # parametrized over SCENARIOS

The same ``SCENARIOS`` table backs both, so the docs, the CLI, and CI never drift.

COVERAGE (categories): ip · typed (domain/role/zone/dynamic/updatable/Internet) · services-l4
(tcp/udp/sctp ports+ranges, service-groups) · services-named (icmp/icmp6, GRE, opaque) · apps
(application-site / category / app-group, carve-out) · placement (floor/provisioned-section/above-deny/
partial/anomaly/Stealth/Dynamic-Layer/disabled/conditional) · removal (disable/deny/no_op/review).
Each ``expect`` is derived from Check Point FIRST-MATCH semantics, independent of the code.
"""
from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass, field

from . import access_automation as aa
from .access_automation import AccessRequest, ServiceSet


# --- compact object / rule factories (a CP object-dictionary is uid -> object dict) ----------------
def host(uid, ip):       return {"uid": uid, "type": "host", "name": uid, "ipv4-address": ip}
def net(uid, sub, ml):   return {"uid": uid, "type": "network", "name": uid, "subnet4": sub, "mask-length4": ml}
def rng(uid, lo, hi):    return {"uid": uid, "type": "address-range", "name": uid, "ipv4-address-first": lo, "ipv4-address-last": hi}
def group(uid, members): return {"uid": uid, "type": "group", "name": uid, "members": list(members)}
def gw(uid, ip):         return {"uid": uid, "type": "simple-gateway", "name": uid, "ipv4-address": ip}
def tcp(uid, port, name=None): return {"uid": uid, "type": "service-tcp", "name": name or uid, "port": str(port)}
def udp(uid, port, name=None): return {"uid": uid, "type": "service-udp", "name": name or uid, "port": str(port)}
def sctp(uid, port, name=None): return {"uid": uid, "type": "service-sctp", "name": name or uid, "port": str(port)}
def icmp(uid, name, v6=False): return {"uid": uid, "type": "service-icmp6" if v6 else "service-icmp", "name": name}
def other(uid, name):    return {"uid": uid, "type": "service-other", "name": name}
def svcgroup(uid, members): return {"uid": uid, "type": "service-group", "name": uid, "members": list(members)}
def appsite(uid, name):  return {"uid": uid, "type": "application-site", "name": name}
def appcat(uid, name):   return {"uid": uid, "type": "application-site-category", "name": name}
def appgroup(uid, name): return {"uid": uid, "type": "application-site-group", "name": name}
def dns(uid, name, sub): return {"uid": uid, "type": "dns-domain", "name": name, "is-sub-domain": sub}
def role(uid, name):     return {"uid": uid, "type": "access-role", "name": name}
def zone(uid, name):     return {"uid": uid, "type": "security-zone", "name": name}
def updatable(uid, name): return {"uid": uid, "type": "updatable-object", "name": name}
def dynobj(uid, name):   return {"uid": uid, "type": "dynamic-object", "name": name}
def dynlayer(uid, name): return {"uid": uid, "name": name, "dynamic-layer": True}   # inline-layer object

ANY = {"uid": "any", "type": "CpmiAnyObject", "name": "Any"}
INTERNET = {"uid": aa._INTERNET_UID, "type": "Internet", "name": "Internet"}


def rule(uid, num, action, src, dst, svc, **kw):
    """A raw access-rule dict (as a live show-access-rulebase yields). ``src``/``dst``/``svc`` are lists of
    object uids (present in the scenario's objects). action: 'Accept'|'Drop'|'Apply Layer'."""
    enabled = kw.pop("enabled", True)
    return {"uid": uid, "rule-number": num, "name": uid, "enabled": enabled, "action": action,
            "source": list(src), "destination": list(dst), "service": list(svc), **kw}


CLEANUP = rule("cleanup", 999, "Drop", ["any"], ["any"], ["any"])   # the Any/Any/Any catch-all floor


@dataclass
class Scenario:
    id: str
    category: str
    desc: str
    objects: list           # object dicts (the object-dictionary)
    rules: list             # raw rule dicts (top-down order)
    request: dict           # AccessRequest kwargs; "src"/"dst" are shorthand for *_cidrs=[...]
    expect: dict            # outcome[, widen_field, position(subset), target, note_contains]
    op: str = "add"         # "add" -> decide(); "remove" -> decide_removal()


def _make_request(spec: dict) -> AccessRequest:
    kw = dict(spec)
    if "src" in kw:
        kw["src_cidrs"] = [kw.pop("src")]
    if "dst" in kw:
        kw["dst_cidrs"] = [kw.pop("dst")]
    kw.setdefault("src_cidrs", [])
    kw.setdefault("dst_cidrs", [])
    return AccessRequest(**kw)


def evaluate(s: Scenario):
    """Run one scenario through the real engine. Returns (passed: bool, actual: dict, detail: str)."""
    od = {o["uid"]: o for o in s.objects}
    rules = [aa._parse_rule(r, od) for r in s.rules]
    req = _make_request(s.request)
    d = aa.decide(req, rules) if s.op == "add" else aa.decide_removal(req, rules)
    actual = {"outcome": d.outcome.value,
              "widen_field": getattr(d, "widen_field", None),
              "position": dict(getattr(d, "position", None) or {}),
              "target": getattr(d.target_rule, "uid", None) if d.target_rule else None,
              "notes": list(d.notes or [])}
    fails = []
    exp = s.expect
    if actual["outcome"] != exp["outcome"]:
        fails.append(f"outcome={actual['outcome']} != {exp['outcome']}")
    if "widen_field" in exp and actual["widen_field"] != exp["widen_field"]:
        fails.append(f"widen_field={actual['widen_field']} != {exp['widen_field']}")
    if "target" in exp and actual["target"] != exp["target"]:
        fails.append(f"target={actual['target']} != {exp['target']}")
    for k, v in (exp.get("position") or {}).items():       # subset match on position keys
        if actual["position"].get(k) != v:
            fails.append(f"position[{k}]={actual['position'].get(k)} != {v}")
    if "note_contains" in exp and not any(exp["note_contains"].lower() in n.lower() for n in actual["notes"]):
        fails.append(f"no note containing {exp['note_contains']!r}")
    return (not fails, actual, "; ".join(fails))


# =================================================================================================
# THE SCENARIO TABLE — every supported object / service / outcome. expect derived from CP semantics.
# =================================================================================================
SCENARIOS: list[Scenario] = [
    # ---------- IP source/destination space ----------
    Scenario("ip-noop-host-in-network", "ip", "a /32 inside a network the rule already allows -> reuse",
             [host("h", "10.1.0.50"), net("n", "10.1.0.0", 24), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["n"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.50/32", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("ip-widen-source", "ip", "two cols equal, source differs -> widen the source CELL",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "192.168.9.9/32", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "widen", "widen_field": "source", "target": "r"}),
    Scenario("ip-widen-destination", "ip", "source+service equal, destination differs -> widen destination",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.99/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "widen", "widen_field": "destination", "target": "r"}),
    Scenario("ip-widen-service", "ip", "source+destination equal, port differs -> widen service",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "8080"},
             {"outcome": "widen", "widen_field": "service", "target": "r"}),
    Scenario("ip-create-nothing-covers", "ip", "no rule covers it -> create at the cleanup floor",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.9.9.9/32", "dst": "8.8.8.8/32", "protocol": "tcp", "ports": "22"},
             {"outcome": "create", "position": {"above": "cleanup"}}),
    Scenario("ip-create-above-covering-deny", "ip", "a resolved covering DROP -> create the allow ABOVE it",
             [host("c", "10.1.2.250"), host("d", "9.9.9.9"), tcp("t", 1521), ANY],
             [rule("dny", 1, "Drop", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.2.250/32", "dst": "9.9.9.9/32", "protocol": "tcp", "ports": "1521"},
             {"outcome": "create", "position": {"above": "dny"}}),
    Scenario("ip-create-above-partial-deny", "ip", "a /32 deny inside a /24 request -> create ABOVE it",
             [net("n", "10.1.1.0", 24), host("dd", "10.1.1.5"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("p", 1, "Drop", ["dd"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.1.0/24", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "create", "position": {"above": "p"}}),
    Scenario("ip-group-source-noop", "ip", "a group source dereferenced to members -> member reuse",
             [host("a", "10.1.0.5"), host("b", "10.1.0.6"), group("g", ["a", "b"]),
              host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["g"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.6/32", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("ip-range-noop", "ip", "a host inside an address-range the rule allows -> reuse",
             [rng("rg", "10.1.0.1", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["rg"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.5/32", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "no_op", "target": "r"}),

    # ---------- typed (non-IP) source/destination ----------
    Scenario("typed-domain-subdomain-noop", "typed", "a .corp.com cell covers api.corp.com -> reuse",
             [host("c", "10.1.0.9"), dns("dm", ".corp.com", True), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["dm"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst_kind": "domain", "dst_value": "api.corp.com", "protocol": "tcp", "ports": "443"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("typed-domain-exact-not-noop-widens", "typed",
             "an exact corp.com cell does NOT cover a domain+subdomains req (not a NO_OP) -> widens the destination",
             [host("c", "10.1.0.9"), dns("dm", "corp.com", False), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["dm"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst_kind": "domain", "dst_value": ".corp.com", "protocol": "tcp", "ports": "443"},
             {"outcome": "widen", "widen_field": "destination", "target": "r"}),
    Scenario("typed-domain-create-cross-kind", "typed",
             "a domain request from an UNRELATED source (differs in 2 dims) -> nothing to reuse -> create",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.2.2.2/32", "dst_kind": "domain", "dst_value": "corp.com", "protocol": "tcp", "ports": "443"},
             {"outcome": "create"}),
    Scenario("typed-role-noop", "typed", "an access-role source matched by exact identity -> reuse",
             [role("ar", "Finance"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["ar"], ["d"], ["t"]), CLEANUP],
             {"src_kind": "access-role", "src_value": "Finance", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("typed-zone-widens-source", "typed",
             "a security-zone source vs a rule whose dest+service equal -> widens the source cell",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src_kind": "security-zone", "src_value": "InternalZone", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "widen", "widen_field": "source", "target": "r"}),
    Scenario("typed-domain-vs-updatable-note", "typed", "domain vs an updatable feed -> note + continue (uncertain)",
             [host("c", "10.1.0.9"), updatable("up", "Office365"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["up"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst_kind": "domain", "dst_value": "outlook.office.com", "protocol": "tcp", "ports": "443"},
             {"outcome": "create", "note_contains": "review"}),

    # ---------- the predefined Internet object (App Control destination) ----------
    Scenario("internet-noop", "internet", "win_server -> Internet -> Facebook already allowed -> reuse",
             [host("ws", "10.1.2.250"), INTERNET, appsite("fb", "Facebook"), ANY],
             [rule("r", 1, "Accept", ["ws"], [INTERNET["uid"]], ["fb"]), CLEANUP],
             {"src": "10.1.2.250/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("internet-widen-source", "internet", "another host wants the same Internet app -> widen source",
             [host("ws", "10.1.2.250"), INTERNET, appsite("fb", "Facebook"), ANY],
             [rule("r", 1, "Accept", ["ws"], [INTERNET["uid"]], ["fb"]), CLEANUP],
             {"src": "10.1.1.222/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "widen", "widen_field": "source", "target": "r"}),
    Scenario("internet-by-bare-uid-widen", "internet", "Internet referenced by bare uid (not in objdict) is still recognized",
             [host("ws", "10.1.2.250"), appsite("fb", "Facebook"), ANY],   # NOTE: Internet object absent from objdict
             [rule("r", 1, "Accept", ["ws"], [aa._INTERNET_UID], ["fb"]), CLEANUP],
             {"src": "10.1.1.222/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "widen", "widen_field": "source", "target": "r"}),
    Scenario("internet-steps-past-stealth", "internet", "Internet dest is disjoint from a gateway IP -> steps past the Stealth rule",
             [host("ws", "10.1.2.250"), INTERNET, appsite("fb", "Facebook"), gw("g", "10.0.0.1"), ANY],
             [rule("st", 1, "Drop", ["any"], ["g"], ["any"]),
              rule("r", 2, "Accept", ["ws"], [INTERNET["uid"]], ["fb"]), CLEANUP],
             {"src": "10.1.1.222/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "widen", "widen_field": "source", "target": "r"}),

    # ---------- services: L4 ----------
    Scenario("svc-tcp-range-noop", "services-l4", "a port inside a rule's tcp range -> reuse",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", "8000-8100", "hi"), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "8080"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("svc-cross-proto-widens", "services-l4",
             "udp/443 is disjoint from a tcp/443 rule (no false NO_OP); src+dst equal -> widens the service",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32", "protocol": "udp", "ports": "443"},
             {"outcome": "widen", "widen_field": "service", "target": "r"}),
    Scenario("svc-sctp-noop", "services-l4", "sctp is port-based -> a matching sctp port reuses",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), sctp("s", 9000), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["s"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32", "protocol": "sctp", "ports": "9000"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("svc-group-noop", "services-l4", "a tcp/443 request inside a service-group {tcp443,tcp80} -> reuse",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t1", 443, "https"), tcp("t2", 80, "http"),
              svcgroup("sg", ["t1", "t2"]), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["sg"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("svc-multikind-create-not-widen", "services-l4",
             "QA BUG-1 guard: a multi-kind service request {tcp443+icmp} a rule covers one leg of -> CREATE, never a single-object WIDEN that drops the icmp leg",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32",
              "svc_set": ServiceSet(by_proto={"tcp": aa._ports_to_iv("443")}, named={("icmp", "echo-request")})},
             {"outcome": "create"}),

    # ---------- services: named / opaque ----------
    Scenario("svc-icmp-noop", "services-named", "an icmp named-service request matched by name -> reuse",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), icmp("ic", "echo-request"), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["ic"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32", "service": "echo-request", "service_kind": "icmp"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("svc-icmp6-not-aliased", "services-named",
             "icmp6 echo-request must NOT alias an icmp(v4) rule of the same name (no false NO_OP) -> widens the service",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), icmp("ic", "echo-request", v6=False), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["ic"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32", "service": "echo-request", "service_kind": "icmp6"},
             {"outcome": "widen", "widen_field": "service", "target": "r"}),
    Scenario("svc-port-vs-opaque-not-overridden", "services-named",
             "a tcp/443 request vs an opaque service-other DROP can't be proven disjoint -> not overridden (placed below + noted)",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), other("o", "GRE"), ANY],
             [rule("dny", 1, "Drop", ["c"], ["d"], ["o"]), CLEANUP],
             {"src": "10.1.0.9/32", "dst": "172.16.5.10/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "create", "note_contains": "review"}),

    # ---------- applications & categories ----------
    Scenario("app-noop", "apps", "an application-site already allowed -> reuse",
             [host("c", "10.1.0.9"), INTERNET, appsite("fb", "Facebook"), ANY],
             [rule("r", 1, "Accept", ["c"], [INTERNET["uid"]], ["fb"]), CLEANUP],
             {"src": "10.1.0.9/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("app-category-noop", "apps", "an application-site-CATEGORY already allowed -> reuse (not a redundant create)",
             [host("c", "10.1.0.9"), INTERNET, appcat("sn", "Social Networking"), ANY],
             [rule("r", 1, "Accept", ["c"], [INTERNET["uid"]], ["sn"]), CLEANUP],
             {"src": "10.1.0.9/32", "application": "Social Networking", "application_kind": "application-site-category",
              "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "no_op", "target": "r"}),
    Scenario("app-category-vs-app-disjoint", "apps", "a single app request is NOT covered by a category rule (can't prove membership)",
             [host("c", "10.1.0.9"), INTERNET, appcat("sn", "Social Networking"), ANY],
             [rule("r", 1, "Accept", ["c"], [INTERNET["uid"]], ["sn"]), CLEANUP],
             {"src": "10.1.0.9/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "create"}),
    Scenario("app-category-vs-same-named-group", "apps", "a category is NOT matched by a same-named application-site-GROUP",
             [host("c", "10.1.0.9"), INTERNET, appgroup("ag", "Social Networking"), ANY],
             [rule("r", 1, "Accept", ["c"], [INTERNET["uid"]], ["ag"]), CLEANUP],
             {"src": "10.1.0.9/32", "application": "Social Networking", "application_kind": "application-site-category",
              "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "create"}),
    Scenario("app-carveout-above-web-drop", "apps", "an app blocked by an http/https (443) DROP -> carve the app ABOVE it",
             [host("c", "10.1.0.9"), tcp("t", 443), ANY],
             [rule("sd", 1, "Drop", ["any"], ["any"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "create", "position": {"above": "sd"}}),
    Scenario("app-vs-nonweb-drop-disjoint", "apps", "an app vs a non-web (SSH/22) DROP is provably disjoint -> not blocked",
             [host("c", "10.1.0.9"), host("d", "172.16.5.10"), tcp("t", 22, "ssh"), ANY],
             [rule("sd", 1, "Drop", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.0.9/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "create", "position": {"above": "cleanup"}}),

    # ---------- placement & rulebase structure ----------
    Scenario("place-exact-deny-shadow-anomaly", "placement",
             "QA BUG-2 guard: overriding an EXACT-covering deny flags a more-specific deny BELOW it",
             [net("n24", "10.1.1.0", 24), host("h32", "10.1.1.5"), net("d", "10.2.0.0", 24), tcp("t", 443), ANY],
             [rule("A", 1, "Drop", ["n24"], ["d"], ["t"]), rule("B", 2, "Drop", ["h32"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.1.0/24", "dst": "10.2.0.0/24", "protocol": "tcp", "ports": "443"},
             {"outcome": "create", "position": {"above": "A", "_anomaly": True}, "note_contains": "B"}),
    Scenario("place-dynamic-layer-widen-below", "placement",
             "regression: a Dynamic Layer high in the rulebase must NOT suppress a widen of a rule BELOW it",
             [dynlayer("dynL", "DynLayer"), host("ws", "10.1.2.250"), INTERNET, appsite("fb", "Facebook"), ANY],
             [rule("dyn", 1, "Apply Layer", ["any"], ["any"], ["any"], **{"inline-layer": "dynL"}),
              rule("r", 2, "Accept", ["ws"], [INTERNET["uid"]], ["fb"]), CLEANUP],
             {"src": "10.1.1.222/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "widen", "widen_field": "source", "target": "r"}),
    Scenario("place-disabled-rule-skip-and-note", "placement",
             "a DISABLED rule that already matches -> CREATE (skipped) + advise re-enabling it",
             [host("ws", "10.1.2.250"), INTERNET, appsite("fb", "Facebook"), ANY],
             [rule("r", 1, "Accept", ["ws"], [INTERNET["uid"]], ["fb"], enabled=False), CLEANUP],
             {"src": "10.1.2.250/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "create", "note_contains": "DISABLED"}),

    # ---------- removal (revoke) ----------
    Scenario("rem-disable-exact", "removal", "exactly one rule grants exactly this access -> DISABLE it",
             [host("c", "10.1.2.250"), host("d", "1.1.1.1"), appsite("fb", "Facebook"), INTERNET, ANY],
             [rule("rx", 1, "Accept", ["c"], ["d"], ["fb"]), CLEANUP],
             {"src": "10.1.2.250/32", "dst": "1.1.1.1/32", "application": "Facebook"},
             {"outcome": "disable", "target": "rx"}, op="remove"),
    Scenario("rem-deny-above-broader", "removal", "a BROADER rule grants it -> insert a Drop ABOVE that rule",
             [net("n", "10.1.2.0", 24), appsite("fb", "Facebook"), ANY],
             [rule("r2", 1, "Accept", ["n"], ["any"], ["fb"]), CLEANUP],
             {"src": "10.1.2.250/32", "dst": "Any", "application": "Facebook"},
             {"outcome": "deny", "position": {"above": "r2"}}, op="remove"),
    Scenario("rem-noop-not-granted", "removal", "the access isn't permitted today -> nothing to remove",
             [host("c", "10.5.5.5"), host("d", "9.9.9.9"), tcp("t", 443), ANY],
             [rule("r", 1, "Accept", ["c"], ["d"], ["t"]), CLEANUP],
             {"src": "10.1.2.250/32", "dst": "1.2.3.4/32", "protocol": "tcp", "ports": "443"},
             {"outcome": "no_op"}, op="remove"),
    Scenario("rem-still-granted-below-deny", "removal",
             "an exact rule but a BROADER one below re-grants it -> DENY (don't under-remove)",
             [host("c", "10.1.2.250"), net("n", "10.1.2.0", 24), appsite("fb", "Facebook"), INTERNET, ANY],
             [rule("ex", 1, "Accept", ["c"], [INTERNET["uid"]], ["fb"]),
              rule("bd", 2, "Accept", ["n"], [INTERNET["uid"]], ["fb"]), CLEANUP],
             {"src": "10.1.2.250/32", "application": "Facebook", "dst_kind": "internet", "dst_value": "Internet"},
             {"outcome": "deny"}, op="remove"),
]


def run(scenarios=SCENARIOS, category=None):
    sel = [s for s in scenarios if not category or s.category == category]
    return [(s, *evaluate(s)) for s in sel]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Access-automation engine QA scenario battery.")
    ap.add_argument("--category", help="run only this category (ip, typed, internet, services-l4, "
                                       "services-named, apps, placement, removal)")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    ap.add_argument("--verbose", "-v", action="store_true", help="show the engine's actual outcome for each")
    a = ap.parse_args(argv)
    if a.list:
        for s in SCENARIOS:
            print(f"  [{s.category:13s}] {s.id:42s} {s.desc}")
        print(f"\n{len(SCENARIOS)} scenarios.")
        return 0
    results = run(category=a.category)
    passed = sum(1 for _, ok, _, _ in results if ok)
    cat = None
    for s, ok, actual, detail in results:
        if s.category != cat:
            cat = s.category
            print(f"\n=== {cat} ===")
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {s.id}"
        if not ok:
            line += f"  -> {detail}"
        elif a.verbose:
            line += f"  ({actual['outcome']}" + (f"/{actual['widen_field']}" if actual['widen_field'] else "") + ")"
        print(line)
    print(f"\n{passed}/{len(results)} passed"
          + (f" ({len(results) - passed} FAILED)" if passed != len(results) else " — all green"))
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
