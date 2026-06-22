"""Ticket-driven access automation: the pure decision engine, rule parsing, the I/O entry points
(preview/execute) against a fake session, ServiceNow payload handling, the webhook auth gate, and
template rendering. No live SMS needed."""
import asyncio
import contextlib
import ipaddress
import types

import pytest

from app.routers import access_automation as aar
from app.routers.ui import templates
from app.services import access_automation as aa
from app.services import decision_tree as dt
from app.services import ticketing as tk
from app.services.access_automation import (
    AccessRequest,
    Outcome,
    ParsedRule,
    Relation,
    ServiceSet,
)

ANY = aa.ANY_IP


# --- helpers ---------------------------------------------------------------------------------
def _host(ip):
    return [(aa._ip_int(ip), aa._ip_int(ip))]


def _net(cidr):
    n = ipaddress.ip_network(cidr)
    return [(int(n.network_address), int(n.broadcast_address))]


def _tcp(p):
    return ServiceSet(by_proto={"tcp": aa._ports_to_iv(str(p))})


def _app(names=None, opaque=False):
    return ServiceSet(apps=set(names or []), opaque=opaque)


def _rule(uid, num, action, src, dst, svc, *, groups=None, dest_groups=None, enabled=True, complex=False,
          conditions=()):
    return ParsedRule(uid=uid, number=num, name=uid, enabled=enabled, action=action,
                      src=src, dst=dst, svc=svc, source_group_uids=groups or [],
                      dest_group_uids=dest_groups or [], complex=complex,
                      conditional=bool(conditions), conditions=tuple(conditions))


WEB = _rule("r8", 8, "Accept", _net("10.1.0.0/24"), _host("172.16.5.10"), _tcp(443),
            groups=["grp-web-src"])
WEB_CELL = _rule("r7", 7, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))  # no group
DENY_DB = _rule("r9", 9, "Drop", ANY, _host("172.16.5.20"), _tcp(1521))
CLEANUP = _rule("rC", 99, "Drop", ANY, ANY, ServiceSet(any=True))


# --- interval / relation primitives ----------------------------------------------------------
def test_relation_subset_superset_disjoint_equal():
    assert aa.relation(_host("10.1.0.5"), _net("10.1.0.0/24")) == Relation.SUBSET
    assert aa.relation(_net("10.1.0.0/24"), _host("10.1.0.5")) == Relation.SUPERSET
    assert aa.relation(_host("10.1.0.5"), _host("10.1.0.5")) == Relation.EQUAL
    assert aa.relation(_host("10.1.0.5"), _host("192.168.0.1")) == Relation.DISJOINT


def test_service_set_covers_and_any():
    assert ServiceSet(any=True).covers(_tcp(443))
    assert not _tcp(443).covers(ServiceSet(any=True))
    assert _tcp("1-1024").covers(_tcp(443))
    assert not _tcp(443).covers(_tcp(80))


# --- decide(): the four outcomes --------------------------------------------------------------
def test_decide_no_op_source_inside_network():
    d = aa.decide(AccessRequest(["10.1.0.50/32"], ["172.16.5.10/32"], "tcp", "443"), [WEB, CLEANUP])
    assert d.outcome is Outcome.NO_OP and d.target_rule.uid == "r8"


def test_decide_widen_source_adds_to_cell_not_group():
    # WEB references a source group, but we widen the rule's CELL (never the shared group) to avoid
    # granting the new source in every other rule that uses that group.
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [WEB, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source" and d.widen_group_uid is None


def test_decide_widen_falls_back_to_source_cell_when_no_group():
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [WEB_CELL, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_group_uid is None and d.target_rule.uid == "r7"
    assert d.widen_field == "source"


def test_decide_widen_destination_when_only_dest_differs():
    # the rule-7.4 case: same source + service, only the destination differs -> widen the DESTINATION
    dns = _rule("r74", 74, "Accept", _host("10.1.2.250"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"), [dns, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "destination"
    assert d.target_rule.uid == "r74" and d.widen_group_uid is None


def test_decide_dest_widen_via_cell_not_group():
    dns = _rule("rg", 74, "Accept", _host("10.1.2.250"), _net("9.9.9.0/24"), _tcp(53),
                dest_groups=["grp-dns-dst"])
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"), [dns, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "destination" and d.widen_group_uid is None


def test_execute_widen_destination_adds_to_rule_dest_cell(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    dns = _rule("r74", 74, "Accept", _host("10.1.2.250"), _host("9.9.9.9"), _tcp(53))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [dns, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"), "DNS", publish=True)
    assert res["outcome"] == "widen" and res["widen_field"] == "destination"
    assert res["widen_object"] == "h-1-1-1-1"
    setr = next(p for c, p in calls if c == "set-access-rule")
    assert setr["uid"] == "r74" and setr["destination"] == {"add": "h-1-1-1-1"}
    assert not any(c == "add-access-rule" for c, _ in calls)   # widened, not created


def test_decide_widen_service_when_only_service_differs():
    # same source + destination, only the service differs -> widen the SERVICE cell
    rule = _rule("rs", 5, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["10.1.0.9/32"], ["172.16.5.10/32"], "tcp", "8443"), [rule, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "service" and d.target_rule.uid == "rs"


def test_execute_widen_service_adds_to_rule_service_cell(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    rule = _rule("rs", 5, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [rule, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.0.9/32"], ["172.16.5.10/32"], "tcp", "8443"), "L", publish=True)
    assert res["outcome"] == "widen" and res["widen_field"] == "service" and res["widen_object"] == "TCP-8443"
    setr = next(p for c, p in calls if c == "set-access-rule")
    assert setr["service"] == {"add": "TCP-8443"} and not any(c == "add-access-rule" for c, _ in calls)


# --- application requests (Facebook / YouTube etc. live in the Services & Applications cell) ----
def test_decide_app_no_op_when_app_already_allowed():
    rule = _rule("ra", 5, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"Facebook"}))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [rule, CLEANUP])
    assert d.outcome is Outcome.NO_OP and d.target_rule.uid == "ra"


def test_decide_app_widens_service_when_app_differs():
    rule = _rule("ra", 5, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app({"YouTube"}))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [rule, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "service"


def test_decide_app_review_on_opaque_category():
    # rule allows an app CATEGORY we can't expand -> we can't tell if Facebook is inside -> REVIEW
    rule = _rule("ra", 5, "Accept", _host("10.1.2.250"), _host("1.1.1.1"), _app(opaque=True))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [rule, CLEANUP])
    assert d.outcome is Outcome.REVIEW


def test_decide_app_create_when_two_dims_differ():
    rule = _rule("ra", 5, "Accept", _host("10.9.9.9"), _host("2.2.2.2"), _app({"Facebook"}))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="Facebook"), [rule, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_execute_app_create_references_app_name_without_creating_it(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    rule = _rule("ra", 5, "Accept", _host("10.9.9.9"), _host("2.2.2.2"), _app({"Facebook"}))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [rule, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], application="YouTube"), "L", publish=True)
    assert res["outcome"] == "create" and res["service_object"] == "YouTube"
    rule_op = next(p for c, p in calls if c == "add-access-rule")
    assert rule_op["service"] == "YouTube"
    assert not any(c in ("add-service-tcp", "add-service-udp") for c, _ in calls)   # apps are predefined


def test_build_request_and_parse_payload_application():
    req = tk.build_request("10.1.2.250", "1.1.1.1", "tcp", "", application="Facebook")
    assert req.application == "Facebook" and req.svc().apps == {"Facebook"}
    t = tk.parse_payload({"server_id": 1, "layer": "L", "source": "10.1.2.250",
                          "destination": "1.1.1.1", "application": "YouTube"})
    assert t.request.application == "YouTube"


def test_decide_create_above_cleanup_for_new_dst():
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"), [WEB, CLEANUP])
    assert d.outcome is Outcome.CREATE
    assert d.position == {"above": "rC"}            # above the catch-all cleanup, never 'bottom'


def test_decide_explicit_deny_is_review_not_override():
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.20/32"], "tcp", "1521"), [DENY_DB, CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "r9"


def test_decide_negated_rule_in_path_is_review():
    weird = _rule("rx", 3, "Accept", _host("172.16.5.10"), _host("172.16.5.10"), _tcp(443), complex=True)
    d = aa.decide(AccessRequest(["172.16.5.10/32"], ["172.16.5.10/32"], "tcp", "443"), [weird, CLEANUP])
    assert d.outcome is Outcome.REVIEW


def test_decide_disabled_rule_is_skipped():
    disabled = _rule("rd", 1, "Accept", ANY, _host("172.16.5.10"), _tcp(443), enabled=False)
    d = aa.decide(AccessRequest(["1.2.3.4/32"], ["172.16.5.10/32"], "tcp", "443"), [disabled, CLEANUP])
    assert d.outcome is Outcome.CREATE         # the disabled covering accept does NOT make it a no-op


def test_decide_no_explicit_cleanup_creates_at_bottom():
    d = aa.decide(AccessRequest(["1.2.3.4/32"], ["9.9.9.9/32"], "tcp", "80"), [WEB])
    assert d.outcome is Outcome.CREATE and d.position == {"_above_cleanup": True}


def test_decide_widen_source_via_cell_first_match():
    # dst + svc equal, source differs -> widen the SOURCE cell of the first matching rule (cell add,
    # never a shared group)
    r1 = _rule("rn", 6, "Accept", _net("10.2.0.0/24"), _host("172.16.5.10"), _tcp(443), groups=["grp-X"])
    r2 = _rule("rg", 7, "Accept", _net("10.3.0.0/24"), _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"),
                  [r1, r2, CLEANUP])
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source"
    assert d.target_rule.uid == "rn" and d.widen_group_uid is None


def test_decide_no_widen_when_source_cell_broader_creates_instead():
    # the rule-7.3 over-grant: source {win_client, win_server}, only win_server requested. Widening the
    # destination would also grant win_client -> 1.1.1.1, so we must CREATE a precise rule instead.
    multi = _rule("r73", 73, "Accept", aa._merge(_host("10.1.2.249") + _host("10.1.2.250")),
                  _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["1.1.1.1/32"], "tcp", "53"), [multi, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_decide_no_widen_when_dest_cell_broader_creates_instead():
    # rule destination is a /24; widening the source would grant the new source the whole /24.
    rule = _rule("rb", 5, "Accept", _host("10.1.0.5"), _net("172.16.5.0/24"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [rule, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_decide_no_widen_when_service_cell_broader_creates_instead():
    # rule allows the whole 1-1024 range; widening the source would grant the new source all of it.
    rule = _rule("rw", 5, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp("1-1024"))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [rule, CLEANUP])
    assert d.outcome is Outcome.CREATE


# --- audit fixes A/B/C: inline layers, mixed port+app service cells, partial drops --------------
def _mixed_svc(port, app):
    return ServiceSet(by_proto={"tcp": aa._ports_to_iv(str(port))}, apps={app})


def test_decide_inline_layer_covering_request_is_review():
    inl = _rule("ri", 2, "Some Inline Layer", _host("10.0.0.5"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["9.9.9.9/32"], "tcp", "53"), [inl, CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "ri"


def test_decide_inline_layer_disjoint_is_create():
    inl = _rule("ri", 2, "Some Inline Layer", _host("10.0.0.5"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["8.8.8.8/32"], "tcp", "53"), [inl, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_svc_relation_mixed_port_app_is_subset_not_equal():
    assert aa.svc_relation(_tcp(443), _mixed_svc(443, "Facebook")) is Relation.SUBSET


def test_decide_no_overgrant_when_service_cell_mixes_port_and_app():
    # rule svc = {tcp/443 + Facebook}; src equal, dst differs. Widening dst would drag Facebook in -> CREATE
    mixed = _rule("rm", 5, "Accept", _host("10.0.0.1"), _host("9.9.9.9"), _mixed_svc(443, "Facebook"))
    d = aa.decide(AccessRequest(["10.0.0.1/32"], ["1.1.1.1/32"], "tcp", "443"), [mixed, CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_decide_no_op_when_port_already_in_mixed_service_cell():
    mixed = _rule("rm", 5, "Accept", _host("10.0.0.1"), _host("9.9.9.9"), _mixed_svc(443, "Facebook"))
    d = aa.decide(AccessRequest(["10.0.0.1/32"], ["9.9.9.9/32"], "tcp", "443"), [mixed, CLEANUP])
    assert d.outcome is Outcome.NO_OP   # rule already permits tcp/443 (plus Facebook) for that exact flow


def test_decide_partial_drop_in_path_is_review():
    # a /32 deny inside the /24 request, above the accept -> first-match drops part of it -> REVIEW
    drop = _rule("d1", 1, "Drop", _host("10.0.0.5"), _host("9.9.9.9"), _tcp(53))
    acc = _rule("a1", 2, "Accept", _net("10.0.0.0/24"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["10.0.0.0/24"], ["9.9.9.9/32"], "tcp", "53"), [drop, acc, CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "d1"


def test_decide_disjoint_drop_does_not_review():
    drop = _rule("d1", 1, "Drop", _host("10.0.0.5"), _host("9.9.9.9"), _tcp(53))
    d = aa.decide(AccessRequest(["192.168.0.0/24"], ["8.8.8.8/32"], "tcp", "53"), [drop, CLEANUP])
    assert d.outcome is Outcome.CREATE


# --- audit fixes D/E + Any endpoints ----------------------------------------------------------
def test_decide_non_bottom_catchall_drop_is_review():
    # an Any/Any/Any DROP that ISN'T the bottom cleanup is an intentional broad block (e.g. lockdown)
    lockdown = _rule("rL", 1, "Drop", ANY, ANY, ServiceSet(any=True))
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["172.16.0.5/32"], "tcp", "443"), [lockdown, CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "rL"


def test_decide_bottom_cleanup_is_the_create_floor():
    d = aa.decide(AccessRequest(["10.0.0.5/32"], ["172.16.0.5/32"], "tcp", "443"), [CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rC"}


def test_decide_opaque_app_drop_reviews_a_port_request():
    # an app category/group DROP might match L7 over tcp/443 -> can't prove it doesn't -> REVIEW
    drop = _rule("rD", 5, "Drop", _host("10.1.1.1"), _host("8.8.8.8"), _app(opaque=True))
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443"), [drop, CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "rD"


def test_decide_opaque_app_accept_does_not_block_a_port_create():
    acc = _rule("rA", 5, "Accept", _host("10.1.1.1"), _host("8.8.8.8"), _app(opaque=True))
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443"), [acc, CLEANUP])
    assert d.outcome is Outcome.CREATE   # an app ACCEPT is harmless to create around (redundant at worst)


def test_build_request_accepts_any_endpoint():
    r = tk.build_request("10.1.2.250", "any", "tcp", "443")
    assert r.dst_cidrs == ["Any"] and r.dst_iv() == aa.ANY_IP
    r2 = tk.build_request("Any", "1.1.1.1", "tcp", "443")
    assert r2.src_cidrs == ["Any"] and r2.src_iv() == aa.ANY_IP


def test_decide_create_with_any_destination():
    d = aa.decide(AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), [CLEANUP])
    assert d.outcome is Outcome.CREATE


def test_execute_any_destination_references_predefined_any(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.2.250/32"], ["Any"], application="Facebook"), "L", publish=True)
    assert res["outcome"] == "create" and res["destination_object"] == "Any"
    rule = next(p for c, p in calls if c == "add-access-rule")
    assert rule["destination"] == "Any"
    assert not any(c == "add-network" for c, _ in calls)   # Any is predefined, never created


# --- audit: IPv6 blindness + empty service ----------------------------------------------------
def test_decide_ipv6_request_is_review_not_create():
    # ANY_IP is the v4 integer range; a v6 endpoint is DISJOINT from every Any/v4 cell, so without a
    # guard the catch-all DROP is invisible and the engine CREATEs an allow above the admin's deny.
    d = aa.decide(AccessRequest(["2001:db8::1/128"], ["2001:db8::2/128"], "tcp", "443"), [CLEANUP])
    assert d.outcome is Outcome.REVIEW and "IPv6" in d.reason


def test_decide_ipv6_with_any_destination_is_review():
    d = aa.decide(AccessRequest(["2001:db8::1/128"], ["Any"], "tcp", "443"), [CLEANUP])
    assert d.outcome is Outcome.REVIEW and "IPv6" in d.reason


def test_build_request_rejects_ipv6():
    with pytest.raises(ValueError, match="IPv6"):
        tk.build_request("2001:db8::1", "172.16.5.10", "tcp", "443")
    with pytest.raises(ValueError, match="IPv6"):
        tk.build_request("10.1.2.250", "2001:db8::/64", "tcp", "443")


def test_decide_empty_service_is_review_not_noop():
    # no concrete service -> empty interval set -> must NOT read as "covered by anything"
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", ""), [WEB_CELL, CLEANUP])
    assert d.outcome is Outcome.REVIEW and "no concrete service" in d.reason


# --- conditional-scope columns (vpn / time / content / install-on / service-resource) ---------
def test_decide_conditional_accept_is_create_not_noop():
    # a VPN-only ACCEPT matching the tuple does NOT permit clear traffic -> CREATE, not NO_OP
    vpn = _rule("rV", 5, "Accept", _host("10.1.1.1"), _host("8.8.8.8"), _tcp(443), conditions=("VPN",))
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443"), [vpn, CLEANUP])
    assert d.outcome is Outcome.CREATE and "VPN" in d.reason and "rV" in d.reason


def test_decide_conditional_drop_overlapping_is_review():
    time_drop = _rule("rT", 5, "Drop", _host("10.1.1.1"), _host("8.8.8.8"), _tcp(443), conditions=("time",))
    d = aa.decide(AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443"), [time_drop, CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "rT" and "time" in d.reason


def test_decide_conditional_accept_is_not_a_widen_target():
    # same dst+svc, source differs by one host: normally a source-widen, but the rule is data-restricted
    cond = _rule("rW", 7, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443), conditions=("data",))
    d = aa.decide(AccessRequest(["10.1.0.10/32"], ["172.16.5.10/32"], "tcp", "443"), [cond, CLEANUP])
    assert d.outcome is Outcome.CREATE   # never widen a rule whose match we can't verify


def test_parse_rule_flags_conditional_columns():
    objd = {
        "u-comm": {"uid": "u-comm", "name": "RemoteAccess", "type": "vpn-community-meshed"},
        "u-time": {"uid": "u-time", "name": "WorkHours", "type": "time"},
    }
    base = {"uid": "r1", "rule-number": 1, "action": "Accept",
            "source": [], "destination": [], "service": []}
    assert aa._parse_rule({**base, "vpn": ["u-comm"]}, objd).conditions == ("VPN",)
    assert aa._parse_rule({**base, "time": ["u-time"]}, objd).conditions == ("time",)
    assert aa._parse_rule({**base, "content": ["u-x"], "content-negate": True}, {}).conditional is True
    assert aa._parse_rule({**base, "install-on": [{"uid": "gw1", "name": "gw1"}]}, {}).conditional is True
    assert aa._parse_rule({**base, "service-resource": "uri-res"}, {}).conditional is True


def test_parse_rule_default_any_cells_are_not_conditional():
    objd = {"u-any": {"uid": "u-any", "name": "Any"},
            "u-pt": {"uid": "u-pt", "name": "Policy Targets"}}
    rule = aa._parse_rule(
        {"uid": "r1", "rule-number": 1, "action": "Accept", "source": [], "destination": [], "service": [],
         "vpn": ["u-any"], "time": ["u-any"], "content": ["u-any"], "install-on": ["u-pt"]}, objd)
    assert rule.conditional is False and rule.conditions == ()


# --- object-type safety net (every cell type the source/dest/service fields can hold) ----------
_OBJD = {
    "any":   {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
    "h8888": {"uid": "h8888", "name": "dns", "type": "host", "ipv4-address": "8.8.8.8"},
    "hsrc":  {"uid": "hsrc", "name": "client", "type": "host", "ipv4-address": "10.1.1.1"},
    "s443":  {"uid": "s443", "name": "https", "type": "service-tcp", "port": "443"},
    "arfin": {"uid": "arfin", "name": "Finance", "type": "access-role"},
    "zone":  {"uid": "zone", "name": "Zone", "type": "security-zone"},
    "uoint": {"uid": "uoint", "name": "Internet", "type": "updatable-object"},
    "hv6":   {"uid": "hv6", "name": "v6", "type": "host", "ipv6-address": "2001:db8::5"},
    "sgre":  {"uid": "sgre", "name": "gre", "type": "service-other", "ip-protocol": 47},
    "sgweb": {"uid": "sgweb", "name": "grp", "type": "service-group", "members": ["s443"]},
}


def _pr(uid, num, action, src, dst, svc):
    return aa._parse_rule({"uid": uid, "rule-number": num, "name": uid, "action": action,
                           "enabled": True, "source": src, "destination": dst, "service": svc}, _OBJD)


_LIVE_CLEANUP = _pr("rC", 99, "Drop", ["any"], ["any"], ["any"])
_OBJ_REQ = AccessRequest(["10.1.1.1/32"], ["8.8.8.8/32"], "tcp", "443")


@pytest.mark.parametrize("src,dst,svc", [
    (["arfin"], ["h8888"], ["s443"]),   # access-role (Identity Awareness) source
    (["zone"],  ["h8888"], ["s443"]),   # security-zone source
    (["uoint"], ["h8888"], ["s443"]),   # updatable-object (Internet / geo)
    (["hv6"],   ["h8888"], ["s443"]),   # an IPv6 host object inside a v4 rule
    # (service-other is now a named+opaque service: create-around an ACCEPT, REVIEW only for a possible
    #  DROP — covered by test_service_other_drop_keeps_port_request_in_path)
])
def test_unenumerable_cell_objects_route_to_review(src, dst, svc):
    # any cell holding an object whose IP/port extent we can't enumerate is "extent-unknown" -> the rule
    # stays in the path and routes to REVIEW; it is NEVER treated as provably disjoint (the v6/CIDR bug class)
    d = aa.decide(_OBJ_REQ, [_pr("rX", 1, "Accept", src, dst, svc), _LIVE_CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "rX"


def test_live_any_object_cleanup_is_recognized_as_floor():
    # the predefined Any object (CpmiAnyObject), as a real cleanup uses -> catch-all -> placement floor
    d = aa.decide(_OBJ_REQ, [_LIVE_CLEANUP])
    assert d.outcome is Outcome.CREATE and d.position == {"above": "rC"}


def test_service_group_members_are_resolved():
    d = aa.decide(_OBJ_REQ, [_pr("rSG", 1, "Accept", ["hsrc"], ["h8888"], ["sgweb"]), _LIVE_CLEANUP])
    assert d.outcome is Outcome.NO_OP and d.target_rule.uid == "rSG"


@pytest.mark.parametrize("extra", [
    {"enable-tcp-resource": True},           # legacy URI/CIFS/FTP resource match
    {"match-by-protocol-signature": True},   # L7 protocol-signature match
    {"source-port": "53"},                   # client-side source-port restriction
])
def test_resource_or_signature_service_is_not_reused(extra):
    # a service that matches more narrowly than its dest port must not be NO_OP'd / widened on the port
    objd = {"u":  {"uid": "u", "name": "narrow-80", "type": "service-tcp", "port": "80", **extra},
            "any": {"uid": "any", "name": "Any", "type": "CpmiAnyObject"},
            "hs":  {"uid": "hs", "name": "c", "type": "host", "ipv4-address": "10.1.2.250"},
            "hd":  {"uid": "hd", "name": "w", "type": "host", "ipv4-address": "172.16.5.10"}}
    acc = aa._parse_rule({"uid": "ra", "rule-number": 1, "name": "narrow", "action": "Accept",
                          "enabled": True, "source": ["hs"], "destination": ["hd"], "service": ["u"]}, objd)
    cleanup = aa._parse_rule({"uid": "rC", "rule-number": 99, "name": "cleanup", "action": "Drop",
                              "enabled": True, "source": ["any"], "destination": ["any"],
                              "service": ["any"]}, objd)
    # same flow (would have been a false NO_OP) and a differing source (would have been an unsafe WIDEN)
    same = aa.decide(AccessRequest(["10.1.2.250/32"], ["172.16.5.10/32"], "tcp", "80"), [acc, cleanup])
    widen = aa.decide(AccessRequest(["192.168.7.7/32"], ["172.16.5.10/32"], "tcp", "80"), [acc, cleanup])
    assert same.outcome is Outcome.REVIEW and same.target_rule.uid == "ra"
    assert widen.outcome is not Outcome.WIDEN


# --- BLOCKER regression: a rule whose extent is UNKNOWN must never be treated as out-of-path -----
def _zone_rule(uid, num, action, dst, svc):
    """An accept/drop whose source is a security-zone / dynamic-object: parses to [] + src_unknown."""
    return ParsedRule(uid=uid, number=num, name=uid, enabled=True, action=action,
                      src=[], dst=dst, svc=svc, src_unknown=True, complex=True)


def test_decide_unresolved_source_accept_is_review_not_widen():
    zone = _zone_rule("rz", 5, "Accept", _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), [zone, CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "rz"


def test_decide_unresolved_drop_above_accept_is_review_not_no_op():
    drop = _zone_rule("rd", 3, "Drop", _host("172.16.5.10"), _tcp(443))
    broad = _rule("rb", 4, "Accept", ANY, _host("172.16.5.10"), _tcp(443))
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"),
                  [drop, broad, CLEANUP])
    assert d.outcome is Outcome.REVIEW and d.target_rule.uid == "rd"


def test_decide_unresolved_rule_on_different_dst_does_not_spurious_review():
    zone_other = _zone_rule("ro", 2, "Accept", _host("10.9.9.9"), _tcp(443))   # provably disjoint dst
    d = aa.decide(AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "80"), [zone_other, CLEANUP])
    assert d.outcome is Outcome.CREATE


# --- placement unit ---------------------------------------------------------------------------
def test_placement_below_more_specific_and_anomaly():
    assert aa._placement(None, WEB) == {"below": "r8"}
    assert aa._position_payload({"below": "r8"}) == {"below": "r8"}
    assert aa._position_payload({"_above_cleanup": True}) == "bottom"
    drop = _rule("rdrop", 5, "Drop", ANY, ANY, ServiceSet(any=True))
    specific = _rule("rs", 10, "Accept", _host("1.1.1.1"), _host("2.2.2.2"), _tcp(1))
    hint = aa._placement(drop, specific)        # specific (10) sits below the cleanup (5)
    assert hint["above"] == "rdrop" and hint["_anomaly"] is True


# --- rule parsing from a show-access-rulebase entry + object dictionary ------------------------
def test_parse_rule_resolves_objdict_group_and_service():
    objdict = {
        "u-grp": {"uid": "u-grp", "name": "g", "type": "group", "members": ["u-h"]},
        "u-h": {"uid": "u-h", "name": "h", "type": "host", "ipv4-address": "10.0.0.5"},
        "u-net": {"uid": "u-net", "name": "n", "type": "network", "subnet4": "172.16.0.0", "mask-length4": 16},
        "u-https": {"uid": "u-https", "name": "https", "type": "service-tcp", "port": "443"},
        "u-accept": {"uid": "u-accept", "name": "Accept", "type": "RulebaseAction"},
    }
    entry = {"type": "access-rule", "rule-number": 4, "name": "allow", "enabled": True, "uid": "r4",
             "source": ["u-grp"], "destination": ["u-net"], "service": ["u-https"], "action": "u-accept"}
    r = aa._parse_rule(entry, objdict)
    assert r.is_accept and r.uid == "r4" and r.source_group_uids == ["u-grp"]
    assert r.src == _host("10.0.0.5")                       # group member resolved
    assert aa.relation(_host("172.16.9.9"), r.dst) == Relation.SUBSET
    assert r.svc.covers(_tcp(443)) and not r.complex


def test_parse_rule_negate_marks_complex():
    objdict = {"u-any": {"uid": "u-any", "name": "Any", "type": "CpmiAnyObject"}}
    entry = {"type": "access-rule", "rule-number": 2, "name": "x", "uid": "r2",
             "source": ["u-any"], "destination": ["u-any"], "service": ["u-any"],
             "action": "Drop", "source-negate": True}
    assert aa._parse_rule(entry, objdict).complex is True


# --- I/O entry points against a fake session --------------------------------------------------
def _fake_session_factory(calls, hosts=None, services=None, fail_on=None):
    hosts = hosts or {}
    services = services or {}

    class FS:
        def __init__(self, server, secret, timeout=30.0, **kwargs):
            self.trace = []

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def call(self, command, payload=None, **kwargs):
            calls.append((command, payload or {}))
            if fail_on and command == fail_on:
                raise aa.MgmtError("server said no")
            if command == "show-objects":
                p = payload or {}
                if (p.get("type") or "").startswith("application-site"):
                    f = p.get("filter") or ""        # echo the searched app so it resolves exactly (it exists)
                    return {"objects": [{"name": f, "uid": "app-" + f, "type": "application-site"}]} if f else {"objects": []}
                ip = p.get("filter")
                return {"objects": [{"name": hosts[ip], "ipv4-address": ip}]} if ip in hosts else {"objects": []}
            if command in ("show-services-tcp", "show-services-udp"):
                proto = "tcp" if command.endswith("tcp") else "udp"
                port = str((payload or {}).get("filter"))
                name = services.get((proto, port))
                return {"objects": [{"name": name, "port": port}]} if name else {"objects": []}
            return {}

        def publish(self):
            calls.append(("publish", {}))

        def discard(self):
            calls.append(("discard", {}))

    return FS


def _fake_read_session(calls, hosts=None, services=None, fail_on=None):
    """A stand-in for mgmt_api.read_session: yields a fake read-only session (the pool/login is mocked
    away). Used by preview tests, which now acquire their session via read_session."""
    factory = _fake_session_factory(calls, hosts=hosts, services=services, fail_on=fail_on)

    @contextlib.contextmanager
    def _rs(server, secret):
        yield factory(server, secret)

    return _rs


def test_execute_widen_adds_to_source_cell(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"),
                     "Network", ticket_id="INC1", publish=True)
    assert res["ok"] and res["outcome"] == "widen" and res["published"] is True
    cmds = [c for c, _ in calls]
    assert "add-host" in cmds and "set-access-rule" in cmds and "publish" in cmds
    assert "set-group" not in cmds and "add-access-rule" not in cmds   # cell add: no group, no new rule
    setr = next(p for c, p in calls if c == "set-access-rule")
    assert setr["source"] == {"add": "h-192-168-9-9"}


def test_execute_create_publishes_rule_and_objects(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"),
                     "Network", ticket_id="INC2", publish=True)
    assert res["ok"] and res["outcome"] == "create" and res["published"] is True
    cmds = [c for c, _ in calls]
    assert cmds.count("add-host") == 2 and "add-service-tcp" in cmds and "add-access-rule" in cmds
    rule = next(p for c, p in calls if c == "add-access-rule")
    assert rule["position"] == {"above": "rC"} and rule["action"] == "Accept"


def test_execute_dry_run_discards(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"),
                     "Network", publish=False)
    assert res["applied"] is True and res["published"] is False and res["validated"] is True
    cmds = [c for c, _ in calls]
    assert "discard" in cmds and "publish" not in cmds


def test_execute_no_op_writes_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.1.0.50/32"], ["172.16.5.10/32"], "tcp", "443"),
                     "Network", publish=True)
    assert res["outcome"] == "no_op" and res["applied"] is False
    assert calls == [] or all(c not in ("add-host", "add-access-rule", "publish") for c, _ in calls)


def test_execute_discards_on_error(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls, fail_on="add-access-rule"))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.9.9/32"], "tcp", "22"),
                     "Network", publish=True)
    assert res["ok"] is False and "server said no" in res["error"]
    cmds = [c for c, _ in calls]
    assert "discard" in cmds and "publish" not in cmds


def test_preview_is_read_only_and_reports_reuse(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "read_session",
                        _fake_read_session(calls, hosts={"192.168.9.9": "existing-host"}))
    monkeypatch.setattr(aa, "load_layer_cached", lambda s, srv, layer, package=None: ([WEB, CLEANUP], False))
    res = aa.preview(object(), "secret",
                     AccessRequest(["192.168.9.9/32"], ["172.16.5.10/32"], "tcp", "443"), "Network")
    assert res["ok"] and res["outcome"] == "widen" and res["widen"]["field"] == "source"
    assert res["widen"]["object"]["exists"] is True and res["widen"]["object"]["name"] == "existing-host"
    cmds = [c for c, _ in calls]
    assert "add-host" not in cmds and "set-group" not in cmds and "publish" not in cmds


def test_execute_cidr_request_materializes_network_not_host(monkeypatch):
    # a /24 source must become a NETWORK object covering the full /24, never a single /32 host
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.50.0.0/24"], ["172.16.5.10/32"], "tcp", "443"),
                     "Network", publish=True)
    assert res["outcome"] == "widen" and res["widen_field"] == "source"
    assert res["widen_object"] == "n-10-50-0-0-24"
    addnet = [p for c, p in calls if c == "add-network"]
    assert addnet and addnet[0]["subnet4"] == "10.50.0.0" and addnet[0]["mask-length4"] == 24
    assert not any(c == "add-host" for c, _ in calls)


def test_execute_cidr_create_uses_network_for_src_and_dst(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "MgmtSession", _fake_session_factory(calls))
    monkeypatch.setattr(aa, "load_layer", lambda s, layer, package=None: [WEB, CLEANUP])
    res = aa.execute(object(), "secret",
                     AccessRequest(["10.50.0.0/24"], ["172.16.9.0/24"], "tcp", "22"),
                     "Network", publish=True)
    assert res["outcome"] == "create"
    assert res["source_object"] == "n-10-50-0-0-24" and res["destination_object"] == "n-172-16-9-0-24"
    assert {p["subnet4"] for c, p in calls if c == "add-network"} == {"10.50.0.0", "172.16.9.0"}


def test_preview_cidr_reports_network_and_stays_read_only(monkeypatch):
    calls = []
    monkeypatch.setattr(aa, "read_session", _fake_read_session(calls))
    monkeypatch.setattr(aa, "load_layer_cached", lambda s, srv, layer, package=None: ([WEB, CLEANUP], False))
    res = aa.preview(object(), "secret",
                     AccessRequest(["10.50.0.0/24"], ["172.16.5.10/32"], "tcp", "443"), "Network")
    assert res["widen"]["object"]["name"] == "n-10-50-0-0-24" and res["widen"]["object"]["ip"] == "10.50.0.0/24"
    assert not any(c in ("add-network", "add-host") for c, _ in calls)   # preview never writes


# --- generic ticketing payload handling -------------------------------------------------------
def test_build_request_normalises_bare_ip_to_cidr():
    req = tk.build_request("192.168.9.9", "172.16.5.10", "TCP", "443")
    assert req.src_cidrs == ["192.168.9.9/32"] and req.dst_cidrs == ["172.16.5.10/32"]
    assert req.protocol == "tcp"


def test_build_request_rejects_bad_input():
    with pytest.raises(ValueError):
        tk.build_request("not-an-ip", "172.16.5.10", "tcp", "443")
    with pytest.raises(ValueError):
        tk.build_request("1.1.1.1", "2.2.2.2", "icmp", "443")
    with pytest.raises(ValueError):
        tk.build_request("1.1.1.1", "2.2.2.2", "tcp", "")


def test_build_request_validates_port_shape():
    # non-numeric, comma list, malformed range, out-of-range, reversed range all rejected at the boundary
    for bad in ["http", "443,80", "1-2-3", "70000", "500-100"]:
        with pytest.raises(ValueError):
            tk.build_request("1.1.1.1", "2.2.2.2", "tcp", bad)
    assert tk.build_request("1.1.1.1", "2.2.2.2", "tcp", "8000-8100").ports == "8000-8100"


def test_parse_payload_flat_and_vendor_aliases():
    t = tk.parse_payload({"ticket_id": "INC1", "server_id": "3", "layer": "Network",
                          "source": "10.0.0.9", "destination": "172.16.5.10",
                          "protocol": "tcp", "port": "443", "apply": "true"})
    assert t.server_id == 3 and t.layer == "Network" and t.apply is True
    assert t.request.dst_cidrs == ["172.16.5.10/32"]
    # ServiceNow-style (number / u_*) and Jira-style (key) aliases both parse
    t2 = tk.parse_payload({"number": "INC2", "u_server_id": 5, "u_layer": "L",
                           "u_source": "10.0.0.0/24", "u_destination": "8.8.8.8",
                           "u_protocol": "udp", "u_port": "53"})
    assert t2.ticket_id == "INC2" and t2.server_id == 5 and t2.apply is False
    assert t2.request.protocol == "udp"
    t3 = tk.parse_payload({"key": "NET-7", "server_id": 2, "layer": "L", "src": "1.1.1.1",
                           "dest": "2.2.2.2", "port": "22", "callback_url": "https://itsm/cb",
                           "callback_token": "tok"})
    assert t3.ticket_id == "NET-7" and t3.callback_url == "https://itsm/cb" and t3.callback_token == "tok"


def test_parse_payload_requires_server_and_layer():
    with pytest.raises(ValueError):
        tk.parse_payload({"layer": "L", "source": "1.1.1.1", "destination": "2.2.2.2", "port": "80"})
    with pytest.raises(ValueError):
        tk.parse_payload({"server_id": 1, "source": "1.1.1.1", "destination": "2.2.2.2", "port": "80"})


def test_summarize_published_and_failed():
    ok = tk.summarize({"ok": True, "outcome": "create", "reason": "r", "source_object": "h-1",
                       "destination_object": "h-2", "service_object": "TCP-22",
                       "position": "above rule 99 (Cleanup rule)", "applied": True, "published": True})
    assert "outcome=create" in ok and "published" in ok and "TCP-22" in ok
    bad = tk.summarize({"ok": False, "error": "boom"})
    assert "FAILED" in bad and "boom" in bad


def test_notify_posts_to_generic_callback_url(monkeypatch):
    captured = {}

    class FakeResp:
        status_code = 200

    class FakeClient:
        def __init__(self, *a, **k):
            captured["verify"] = k.get("verify")

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def post(self, url, json=None, headers=None):
            captured.update(url=url, json=json, headers=headers)
            return FakeResp()

    monkeypatch.setattr(tk.httpx, "Client", FakeClient)
    ticket = tk.parse_payload({"ticket_id": "INC9", "server_id": 1, "layer": "L", "source": "1.1.1.1",
                               "destination": "2.2.2.2", "port": "22", "callback_url": "https://itsm/cb",
                               "callback_token": "t0k"})
    res = tk.notify(ticket, {"ok": True, "outcome": "create", "reason": "r",
                             "applied": True, "published": True})
    assert res["ok"] and res["via"] == "callback_url"
    assert captured["url"] == "https://itsm/cb" and captured["verify"] is True   # TLS never disabled
    assert captured["headers"]["X-DCSim-Token"] == "t0k"
    assert captured["json"]["ticket_id"] == "INC9" and captured["json"]["outcome"] == "create"


def test_notify_skips_when_nothing_configured(monkeypatch):
    monkeypatch.setattr(tk, "servicenow_configured", lambda: False)
    ticket = tk.parse_payload({"ticket_id": "INC9", "server_id": 1, "layer": "L",
                               "source": "1.1.1.1", "destination": "2.2.2.2", "port": "22"})
    assert "skipped" in tk.notify(ticket, {"ok": True, "outcome": "no_op"})


# --- webhook auth gate (route function, no DB needed for these branches) ----------------------
def _run(coro):
    return asyncio.run(coro)


def test_webhook_disabled_without_token(monkeypatch):
    monkeypatch.setattr(aar, "get_settings", lambda: types.SimpleNamespace(webhook_token=""))
    req = types.SimpleNamespace(headers={})
    resp = _run(aar.aa_webhook(req, db=None))
    assert resp.status_code == 503


def test_webhook_rejects_bad_token(monkeypatch):
    monkeypatch.setattr(aar, "get_settings", lambda: types.SimpleNamespace(webhook_token="s3cret"))
    req = types.SimpleNamespace(headers={"x-dcsim-token": "wrong"})
    resp = _run(aar.aa_webhook(req, db=None))
    assert resp.status_code == 401


def test_webhook_server_allowlist_parsing(monkeypatch):
    monkeypatch.setattr(aar, "get_settings",
                        lambda: types.SimpleNamespace(webhook_server_ids="1, 3 ,x,5"))
    assert aar._allowed_server_ids() == {1, 3, 5}
    monkeypatch.setattr(aar, "get_settings", lambda: types.SimpleNamespace(webhook_server_ids=""))
    assert aar._allowed_server_ids() == set()   # blank = no restriction


# --- template rendering -----------------------------------------------------------------------
def _render(name, **ctx):
    ctx.setdefault("request", None)
    return templates.env.get_template(name).render(**ctx)


def test_access_automation_list_renders():
    ms = types.SimpleNamespace(id=1, name="SMS-A", host="10.0.0.1", port=443, domain="")
    html = _render("access_automation_list.html", rows=[{"ms": ms, "has_secret": True}], flash=None)
    assert "Access automation" in html and 'href="/access-automation/1"' in html


def test_access_automation_detail_renders_form_and_webhook():
    ms = types.SimpleNamespace(id=7, name="SMS-B", host="10.0.0.2", port=443, domain="dom1")
    req = types.SimpleNamespace(base_url="https://portal.example/")
    html = _render("access_automation_detail.html", ms=ms, has_secret=True, flash=None, request=req,
                   decision_mermaid_dark=dt.to_mermaid(dark=True), decision_mermaid_light=dt.to_mermaid())
    assert "Preview decision" in html and "aa-source" in html
    assert "/access-automation/webhook" in html and "X-DCSim-Token" in html
    assert "callback_url" in html and "any ITSM" in html
    # the "behind the scenes" decision tree — now a Mermaid render of the engine's own tree,
    # exportable to the user's diagram tool
    assert 'id="aa-flow-dt"' in html and "How it decides" in html
    assert "/access-automation/decision-tree/drawio" in html and "decision-tree/mmd" in html
    for leaf in ("No-op", "Widen the rule", "Create least-privilege rule", "Review"):
        assert leaf in html        # leaf labels live in the embedded Mermaid source


def test_access_automation_diagram_shows_without_credential():
    ms = types.SimpleNamespace(id=9, name="No-Secret", host="10.0.0.9", port=443, domain="")
    req = types.SimpleNamespace(base_url="https://portal.example/")
    html = _render("access_automation_detail.html", ms=ms, has_secret=False, flash=None, request=req,
                   decision_mermaid_dark=dt.to_mermaid(dark=True), decision_mermaid_light=dt.to_mermaid())
    # the explainer is educational, so it renders even when policy can't be pulled
    assert 'id="aa-flow-dt"' in html and "How it decides" in html


# --- group dereferencing: an unresolved group source must REVIEW; a resolved one must not block -----
def _dns_layer(group_members):
    """A DNS-style layer mirroring the live demo: rule 1 has a group source (internal_nets), rule 6 is
    the Facebook allow (win_server -> Any). `group_members` is the group's resolved member list."""
    od = {
        "u-net": {"uid": "u-net", "type": "network", "name": "net_203_0_113_0_24",
                  "subnet4": "203.0.113.0", "mask-length4": 24},
        "u-grp": {"uid": "u-grp", "type": "group", "name": "internal_nets", "members": group_members},
        "u-ws": {"uid": "u-ws", "type": "host", "name": "win_server", "ipv4-address": "10.1.1.50"},
        "u-any": {"uid": "u-any", "type": "CpmiAnyObject", "name": "Any"},
        "u-fb": {"uid": "u-fb", "type": "application-site", "name": "Facebook"},
        "u-acc": {"uid": "u-acc", "name": "Accept"}, "u-drop": {"uid": "u-drop", "name": "Drop"},
    }
    raw = [
        {"uid": "r1", "rule-number": 1, "name": "Internal DNS Server", "enabled": True,
         "source": ["u-net", "u-grp"], "destination": ["u-ws"], "service": ["u-any"], "action": "u-acc"},
        {"uid": "r6", "rule-number": 6, "name": "Facebook allow", "enabled": True,
         "source": ["u-ws"], "destination": ["u-any"], "service": ["u-fb"], "action": "u-acc"},
        {"uid": "r7", "rule-number": 7, "name": "DNS log and drop", "enabled": True,
         "source": ["u-any"], "destination": ["u-any"], "service": ["u-any"], "action": "u-drop"},
    ]
    return [aa._parse_rule(e, od) for e in raw]


_FB_REQ = AccessRequest(src_cidrs=["10.1.1.222/32"], dst_cidrs=["0.0.0.0/0"], application="Facebook")


def test_unresolved_group_source_routes_to_review():
    # group members absent (bare UID) -> source extent unknown -> rule 1 complex -> REVIEW (safety guard)
    rules = _dns_layer(["u-missing-member"])
    assert rules[0].complex and rules[0].src_unknown
    d = aa.decide(_FB_REQ, rules)
    assert d.outcome is Outcome.REVIEW and d.target_rule.number == 1


def test_dereferenced_group_source_lets_engine_widen():
    # group members nested as full objects (what dereference-group-members returns), and 10.1.1.222 is
    # NOT among them -> rule 1 resolves + is disjoint -> engine reaches the clean WIDEN on the FB rule.
    member = {"uid": "u-mem", "type": "host", "name": "an_internal_host", "ipv4-address": "10.1.1.99"}
    rules = _dns_layer([member])
    assert not rules[0].complex and not rules[0].src_unknown
    d = aa.decide(_FB_REQ, rules)
    assert d.outcome is Outcome.WIDEN and d.target_rule.number == 6 and d.widen_field == "source"


# --- network-cell resolution: infra objects (gateway/cluster/mgmt) resolve; opaque objects REVIEW -----
def _od_infra():
    return {
        "h": {"uid": "h", "type": "host", "name": "win_server", "ipv4-address": "10.1.1.50"},
        "gw": {"uid": "gw", "type": "simple-gateway", "name": "GW", "ipv4-address": "10.1.1.1"},
        "sms": {"uid": "sms", "type": "checkpoint-host", "name": "SMS", "ipv4-address": "10.1.1.100"},
        "rng": {"uid": "rng", "type": "address-range", "name": "r",
                "ipv4-address-first": "10.2.0.1", "ipv4-address-last": "10.2.0.9"},
        "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
        "fb": {"uid": "fb", "type": "application-site", "name": "Facebook"},
        "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
        "zone": {"uid": "zone", "type": "security-zone", "name": "InternalZone"},
        "dyn": {"uid": "dyn", "type": "dynamic-object", "name": "DynSrv"},
        "role": {"uid": "role", "type": "access-role", "name": "Finance"},
        "wild": {"uid": "wild", "type": "wildcard", "name": "odd",
                 "ipv4-address": "10.0.0.0", "ipv4-mask-wildcard": "0.0.255.0"},
    }


def _irule(n, src, dst, svc, act, od):
    return aa._parse_rule({"uid": f"r{n}", "rule-number": n, "name": f"r{n}", "enabled": True,
                           "source": src, "destination": dst, "service": svc, "action": act}, od)


def test_gateway_and_checkpoint_host_resolve_as_approx():
    od = _od_infra()
    r = _irule(1, ["h", "gw", "sms"], ["any"], ["any"], "acc", od)
    assert not r.complex          # gateway + checkpoint-host now resolve to their ipv4-address
    assert r.src_approx           # ...but flagged approx (main IP only)
    assert not r.src_unknown


def test_range_resolves_exact_not_approx():
    od = _od_infra()
    r = _irule(1, ["rng"], ["any"], ["any"], "acc", od)
    assert not r.complex and not r.src_approx


def test_opaque_network_objects_still_review():
    od = _od_infra()
    req = AccessRequest(src_cidrs=["10.9.9.9/32"], dst_cidrs=["0.0.0.0/0"], application="Facebook")
    for opaque in ("zone", "dyn", "role", "wild"):
        rules = [_irule(1, [opaque], ["any"], ["any"], "acc", od),
                 _irule(2, ["any"], ["any"], ["any"], "drp", od)]
        assert rules[0].complex, opaque
        assert aa.decide(req, rules).outcome is Outcome.REVIEW, opaque


def test_approx_accept_is_harmless_request_widens_later_rule():
    od = _od_infra()
    rules = [_irule(1, ["gw", "sms"], ["any"], ["any"], "acc", od),    # approx accept, disjoint source
             _irule(2, ["h"], ["any"], ["fb"], "acc", od),             # the real widen target
             _irule(3, ["any"], ["any"], ["any"], "drp", od)]
    req = AccessRequest(src_cidrs=["10.4.4.4/32"], dst_cidrs=["0.0.0.0/0"], application="Facebook")
    d = aa.decide(req, rules)
    assert d.outcome is Outcome.WIDEN and d.target_rule.number == 2 and d.widen_field == "source"


def test_approx_drop_never_under_approximates():
    od = _od_infra()
    rules = [_irule(1, ["gw"], ["any"], ["any"], "drp", od),           # deny from a (multi-homable) gateway
             _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    req = AccessRequest(src_cidrs=["10.7.7.7/32"], dst_cidrs=["0.0.0.0/0"], application="Facebook")
    assert aa.decide(req, rules).outcome is Outcome.REVIEW   # can't prove disjoint from an approx deny


def test_malformed_port_reviews_not_crashes():
    # _ports_to_iv must tolerate garbage (mirror the rule-side _parse_port) so decide() guard 2 -> REVIEW
    assert aa._ports_to_iv("443x") == [] and aa._ports_to_iv("443-abc") == [] and aa._ports_to_iv("-1x") == []
    od = {"any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"}, "drp": {"uid": "drp", "name": "Drop"}}
    rules = [_irule(1, ["any"], ["any"], ["any"], "drp", od)]
    for bad in ("443x", "443-abc", "abc"):          # FULLY unparsable -> empty service -> guard 2 -> REVIEW
        req = AccessRequest(src_cidrs=["10.1.1.1/32"], dst_cidrs=["0.0.0.0/0"], protocol="tcp", ports=bad)
        assert aa.decide(req, rules).outcome is Outcome.REVIEW, bad
    # partial ("443,xyz" keeps the valid 443) is a real request -> a normal decision, just never a crash
    req = AccessRequest(src_cidrs=["10.1.1.1/32"], dst_cidrs=["0.0.0.0/0"], protocol="tcp", ports="443,xyz")
    assert aa.decide(req, rules).outcome in (Outcome.CREATE, Outcome.NO_OP, Outcome.WIDEN, Outcome.REVIEW)


# --- named (non-tcp/udp) services: resolve like apps + reason by name ------------------------------
_SVC_OD = {
    "h": {"uid": "h", "type": "host", "name": "h", "ipv4-address": "10.0.0.5"},
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "t443": {"uid": "t443", "type": "service-tcp", "name": "https", "port": "443"},
    "echo": {"uid": "echo", "type": "service-icmp", "name": "echo-request"},
    "gre": {"uid": "gre", "type": "service-other", "name": "GRE"},
    "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
}


def test_icmp_request_disjoint_from_tcp_rule_creates():
    rules = [_irule(1, ["h"], ["any"], ["t443"], "acc", _SVC_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SVC_OD)]
    # different source so there's no exact-two-cell widen candidate; icmp ≠ tcp/443 -> create
    req = AccessRequest(src_cidrs=["10.9.9.9/32"], dst_cidrs=["0.0.0.0/0"], service="echo-request", service_kind="icmp")
    assert aa.decide(req, rules).outcome is Outcome.CREATE     # icmp not covered by the tcp/443 rule


def test_named_service_already_permitted_is_no_op():
    rules = [_irule(1, ["any"], ["any"], ["echo"], "acc", _SVC_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SVC_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["0.0.0.0/0"], service="echo-request", service_kind="icmp")
    assert aa.decide(req, rules).outcome is Outcome.NO_OP


def test_named_service_widens_exact_two_cells():
    # rule: src h, dst Any, svc echo-request, Accept ; request src 10.0.0.9 -> widen the source
    rules = [_irule(1, ["h"], ["any"], ["echo"], "acc", _SVC_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SVC_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.9/32"], dst_cidrs=["0.0.0.0/0"], service="echo-request", service_kind="icmp")
    d = aa.decide(req, rules)
    assert d.outcome is Outcome.WIDEN and d.widen_field == "source"


def test_service_other_drop_keeps_port_request_in_path():
    # a DROP whose service is service-other (ambiguous protocol) must not be assumed disjoint from a
    # tcp/443 request -> REVIEW (never step over a possible deny).
    rules = [_irule(1, ["any"], ["any"], ["gre"], "drp", _SVC_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SVC_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["0.0.0.0/0"], protocol="tcp", ports="443")
    assert aa.decide(req, rules).outcome is Outcome.REVIEW


# --- SCTP is PORT-based (a real port), not a portless named service like ICMP ---------------------
_SCTP_OD = {
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "s9000": {"uid": "s9000", "type": "service-sctp", "name": "sctp-9000", "port": "9000"},
    "t9000": {"uid": "t9000", "type": "service-tcp", "name": "tcp-9000", "port": "9000"},
    "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
}


def test_sctp_rule_parses_to_by_proto_not_named():
    r = _irule(1, ["any"], ["any"], ["s9000"], "acc", _SCTP_OD)
    assert r.svc.by_proto.get("sctp") == [(9000, 9000)]      # keyed by value under its own protocol
    assert not r.svc.named                                   # NOT a named service


def test_sctp_request_no_op_by_port():
    rules = [_irule(1, ["any"], ["any"], ["s9000"], "acc", _SCTP_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SCTP_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["0.0.0.0/0"], protocol="sctp", ports="9000")
    assert aa.decide(req, rules).outcome is Outcome.NO_OP


def test_sctp_disjoint_from_same_port_tcp_rule_creates():
    # sctp/9000 must NEVER be read as covered by a tcp/9000 rule (distinct protocols)
    rules = [_irule(1, ["any"], ["any"], ["t9000"], "acc", _SCTP_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _SCTP_OD)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["0.0.0.0/0"], protocol="sctp", ports="9000")
    assert aa.decide(req, rules).outcome is Outcome.CREATE


def test_icmp_still_parses_to_named_not_by_proto():
    r = _irule(1, ["any"], ["any"], ["echo"], "acc", _SVC_OD)
    assert ("icmp", "echo-request") in r.svc.named and not r.svc.by_proto   # portless -> named


def test_build_request_accepts_sctp_rejects_other_protocols():
    assert tk.build_request("1.1.1.1", "2.2.2.2", "sctp", "9000").protocol == "sctp"
    for bad in ("icmp", "gre", "esp"):
        with pytest.raises(ValueError):
            tk.build_request("1.1.1.1", "2.2.2.2", bad, "9000")


def test_build_request_named_service_and_precedence():
    r = tk.build_request("10.0.0.5", "Any", "tcp", "", service="icmp")
    assert r.service == "icmp" and r.application is None
    r2 = tk.build_request("10.0.0.5", "Any", "tcp", "443", application="Facebook", service="icmp")
    assert r2.application == "Facebook" and r2.service is None     # application wins


# --- service protocol-family must not alias (v4 icmp != v6 icmp of the same name) ------------------
def test_named_service_family_not_aliased():
    od = dict(_SVC_OD)
    od["echo6"] = {"uid": "echo6", "type": "service-icmp6", "name": "echo-request"}  # same NAME, v6 family
    # rule allows the v6 echo-request; a v4 (icmp) echo-request request must NOT be read as covered
    rules = [_irule(1, ["any"], ["any"], ["echo6"], "acc", od),
             _irule(2, ["any"], ["any"], ["any"], "drp", od)]
    req = AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["0.0.0.0/0"],
                        service="echo-request", service_kind="icmp")
    assert aa.decide(req, rules).outcome is Outcome.CREATE     # not NO_OP — different protocol family


# --- configurable aggressiveness (DecideOptions) ---------------------------------------------------
_DENY_OD = {
    "h": {"uid": "h", "type": "host", "name": "h", "ipv4-address": "10.0.0.5"},
    "any": {"uid": "any", "type": "CpmiAnyObject", "name": "Any"},
    "t443": {"uid": "t443", "type": "service-tcp", "name": "https", "port": "443"},
    "acc": {"uid": "acc", "name": "Accept"}, "drp": {"uid": "drp", "name": "Drop"},
}


def _req443():
    return AccessRequest(src_cidrs=["10.0.0.5/32"], dst_cidrs=["0.0.0.0/0"], protocol="tcp", ports="443")


def test_override_deny_off_reviews_on_off_creates_above():
    # a specific (non-cleanup) covering DROP
    rules = [_irule(1, ["h"], ["any"], ["t443"], "drp", _DENY_OD),
             _irule(2, ["any"], ["any"], ["any"], "drp", _DENY_OD)]
    assert aa.decide(_req443(), rules).outcome is Outcome.REVIEW                      # default: safe
    d = aa.decide(_req443(), rules, aa.DecideOptions(override_deny=True))
    assert d.outcome is Outcome.CREATE and d.position == {"above": "r1"}             # opt-in: create above


def test_ignore_conditions_lets_conditional_accept_cover():
    # a conditional (time-scoped) ACCEPT that covers the request
    raw = {"uid": "r1", "rule-number": 1, "name": "biz-hours", "enabled": True,
           "source": ["any"], "destination": ["any"], "service": ["t443"], "action": "acc",
           "time": ["worktime"]}
    od = dict(_DENY_OD, worktime={"uid": "worktime", "type": "time", "name": "WorkHours"})
    r1 = aa._parse_rule(raw, od)
    cleanup = _irule(2, ["any"], ["any"], ["any"], "drp", od)
    assert r1.conditional                                                            # it IS conditional
    assert aa.decide(_req443(), [r1, cleanup]).outcome is Outcome.CREATE             # default: skip -> create
    assert aa.decide(_req443(), [r1, cleanup], aa.DecideOptions(ignore_conditions=True)).outcome is Outcome.NO_OP


# --- inline-layer recursion ("Apply Layer") --------------------------------------------------------
def _inline(uid, num, src, dst, svc, sub, *, cleanup="drop", name=None, conditions=()):
    """An 'Apply Layer' parent rule whose inline-layer sub-rulebase (`sub`) is already attached, as the
    loader would. `cleanup` is the inline layer's implicit-cleanup-action."""
    return ParsedRule(uid=uid, number=num, name=uid, enabled=True, action="Apply Layer",
                      src=src, dst=dst, svc=svc, conditional=bool(conditions), conditions=tuple(conditions),
                      inline_uid=f"{uid}-L", inline_layer_name=name or f"{uid}-inline",
                      inline_rules=list(sub), inline_cleanup=cleanup)


def _req(src="10.1.0.5/32", dst="172.16.5.10/32", proto="tcp", port="443"):
    return AccessRequest(src_cidrs=[src], dst_cidrs=[dst], protocol=proto, ports=port)


# parent gates the whole 10.1.0.0/24 -> 172.16.5.10 :443 domain into the inline layer
def _parent(sub, **kw):
    return _inline("p1", 5, _net("10.1.0.0/24"), _host("172.16.5.10"), _tcp(443), sub, **kw)


def test_inline_explicit_accept_inside_is_no_op():
    sub = [_rule("i1", 1, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))]
    d = aa.decide(_req(), [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.NO_OP and "inline layer" in d.reason


# a sub rule that neither covers NOR widens the request (differs in dst AND svc) -> forces the inline
# layer's own implicit cleanup to be the verdict
_NONMATCH_SUB = [_rule("i1", 1, "Accept", _host("10.1.0.9"), _host("8.8.8.8"), _tcp(22))]


def test_inline_no_match_drop_cleanup_creates_inside_layer():
    d = aa.decide(_req(), [_parent(_NONMATCH_SUB, cleanup="drop"), CLEANUP])
    assert d.outcome is Outcome.CREATE
    assert d.layer == "p1-inline"                          # the change lands INSIDE the inline layer
    assert "above its drop cleanup" in d.reason


def test_inline_no_match_accept_cleanup_is_no_op():
    d = aa.decide(_req(), [_parent(_NONMATCH_SUB, cleanup="accept"), CLEANUP])
    assert d.outcome is Outcome.NO_OP and "implicit cleanup (accept)" in d.reason


def test_inline_no_match_unknown_cleanup_reviews():
    d = aa.decide(_req(), [_parent(_NONMATCH_SUB, cleanup=""), CLEANUP])
    assert d.outcome is Outcome.REVIEW and "implicit cleanup is unknown" in d.reason


def test_inline_partial_match_splits_to_review():
    # request dst (a /24) is a SUPERSET of the parent's /32 -> traffic splits across layers
    req = AccessRequest(src_cidrs=["10.1.0.5/32"], dst_cidrs=["172.16.5.0/24"], protocol="tcp", ports="443")
    sub = [_rule("i1", 1, "Accept", ANY, ANY, _tcp(443))]
    d = aa.decide(req, [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.REVIEW and "splits across" in d.reason


def test_inline_widen_targets_a_rule_inside_the_layer():
    # inline rule equals request in dst+svc, differs only in source -> WIDEN that inline rule
    sub = [_rule("i1", 1, "Accept", _host("10.1.0.9"), _host("172.16.5.10"), _tcp(443))]
    req = AccessRequest(src_cidrs=["10.1.0.5/32"], dst_cidrs=["172.16.5.10/32"], protocol="tcp", ports="443")
    d = aa.decide(req, [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.WIDEN
    assert d.target_rule.uid == "i1" and d.layer == "p1-inline"


def test_inline_explicit_drop_inside_reviews_then_override_creates():
    sub = [_rule("i1", 1, "Drop", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))]
    assert aa.decide(_req(), [_parent(sub), CLEANUP]).outcome is Outcome.REVIEW
    d = aa.decide(_req(), [_parent(sub), CLEANUP], aa.DecideOptions(override_deny=True))
    assert d.outcome is Outcome.CREATE and d.layer == "p1-inline"


def test_inline_conditional_parent_reviews_unless_ignored():
    sub = [_rule("i1", 1, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))]
    parent = _parent(sub, conditions=("time",))
    assert aa.decide(_req(), [parent, CLEANUP]).outcome is Outcome.REVIEW
    d = aa.decide(_req(), [parent, CLEANUP], aa.DecideOptions(ignore_conditions=True))
    assert d.outcome is Outcome.NO_OP


def test_inline_parent_disjoint_is_not_entered():
    # request outside the parent's domain -> never descends; falls to a normal CREATE at the cleanup
    sub = [_rule("i1", 1, "Drop", ANY, ANY, ServiceSet(any=True))]   # would block if (wrongly) entered
    req = AccessRequest(src_cidrs=["192.168.50.5/32"], dst_cidrs=["8.8.8.8/32"], protocol="tcp", ports="53")
    d = aa.decide(req, [_parent(sub), CLEANUP])
    assert d.outcome is Outcome.CREATE and d.layer is None


def test_inline_nested_two_levels():
    inner = [_rule("j1", 1, "Accept", _host("10.1.0.5"), _host("172.16.5.10"), _tcp(443))]
    mid = [_inline("m1", 1, _net("10.1.0.0/24"), _host("172.16.5.10"), _tcp(443), inner, name="mid")]
    d = aa.decide(_req(), [_parent(mid), CLEANUP])
    assert d.outcome is Outcome.NO_OP


# --- loader: attach inline sub-rulebases (I/O), with cycle + cleanup guards -------------------------
class _FakeSession:
    """Minimal stand-in for MgmtSession.call covering the loader's show-access-rulebase / -layer calls.
    `layers` maps a layer NAME -> its rulebase; `objs` is the shared object dictionary returned with every
    rulebase page (so the inline-layer name resolves like a real pull); `cleanups` maps a layer UID -> its
    implicit-cleanup-action for the show-access-layer fallback."""
    def __init__(self, layers, objs=None, cleanups=None):
        self.layers, self.objs, self.cleanups, self.calls = layers, objs or [], cleanups or {}, []

    def call(self, cmd, payload):
        self.calls.append((cmd, payload))
        if cmd == "show-access-rulebase":
            return {"rulebase": self.layers.get(payload.get("name"), []),
                    "objects-dictionary": self.objs, "total": 0, "to": 0}
        if cmd == "show-access-layer":
            return {"implicit-cleanup-action": self.cleanups.get(payload.get("uid"), "")}
        return {}


def _ap_rule(uid, num, inline_uid):
    return {"type": "access-rule", "uid": uid, "rule-number": num, "name": uid, "enabled": True,
            "source": ["Any"], "destination": ["Any"], "service": ["Any"], "action": "Apply Layer",
            "inline-layer": inline_uid}


def test_loader_attaches_inline_rules_and_cleanup():
    # object dictionary names the inline layer (so the pull uses its name); cleanup is NOT in the dict,
    # so the loader falls back to a show-access-layer lookup.
    objs = [{"uid": "L-DMZ", "type": "access-layer", "name": "DMZ"}]
    top = [_ap_rule("p", 1, "L-DMZ")]
    dmz = [{"type": "access-rule", "uid": "d1", "rule-number": 1, "name": "d1", "enabled": True,
            "source": ["Any"], "destination": ["Any"], "service": ["Any"], "action": "Accept"}]
    sess = _FakeSession({"DMZ": dmz, "topL": top}, objs=objs, cleanups={"L-DMZ": "drop"})
    rules = aa.load_layer(sess, "topL")
    assert rules[0].inline_layer_name == "DMZ"             # resolved from the object dictionary
    assert rules[0].inline_rules is not None and len(rules[0].inline_rules) == 1
    assert rules[0].inline_cleanup == "drop"               # looked up via show-access-layer fallback
    assert ("show-access-layer", {"uid": "L-DMZ"}) in sess.calls


def test_loader_cleanup_from_object_dictionary_skips_lookup():
    # cleanup carried in the object dictionary -> no extra show-access-layer call
    objs = [{"uid": "L-DMZ", "type": "access-layer", "name": "DMZ", "implicit-cleanup-action": "Accept"}]
    sess = _FakeSession({"DMZ": [], "topL": [_ap_rule("p", 1, "L-DMZ")]}, objs=objs)
    rules = aa.load_layer(sess, "topL")
    assert rules[0].inline_cleanup == "accept"
    assert not any(c[0] == "show-access-layer" for c in sess.calls)


def test_loader_cycle_guard_does_not_recurse_forever():
    # an inline layer whose rulebase re-applies itself -> the visited-uid guard stops the recursion
    objs = [{"uid": "L-LOOP", "type": "access-layer", "name": "LOOP"}]
    selfref = [_ap_rule("s", 1, "L-LOOP")]
    sess = _FakeSession({"LOOP": selfref, "topL": selfref}, objs=objs, cleanups={"L-LOOP": "drop"})
    rules = aa.load_layer(sess, "topL")        # must terminate
    assert rules[0].inline_rules is not None    # attached; the self-reference inside resolves to []
    assert rules[0].inline_rules[0].inline_rules == []   # the cycle was cut at the second encounter
