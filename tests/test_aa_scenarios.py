"""Access-automation ENGINE scenario battery — a living QA dataset.

A table of realistic Check-Point-lab-shaped scenarios (rulebase + request + the SE-correct outcome) run
against the pure engine (decide / decide_removal). Born from the 2026-06-24 QA workflow that found the
over/under-conservatism around UNRELATED rules whose only link to a request is an approx (gateway main-IP),
updatable-object, or App-Control (app-vs-L4) CAVEAT. The boundary guards here (resolved-disjoint vs caveat-
disjoint; disjoint-source vs same-src+dst; above vs below the grant) are the highest-value locks — they pin
exactly where conservatism must and must NOT fire, so the three call sites (decide / decide_removal /
_still_granted_below) can't drift apart again. Reuses the helpers in test_access_automation."""
import pytest

from test_access_automation import _rule, _host, _net, _app, _tcp, _mixed_svc, ANY, CLEANUP
from app.services.access_automation import (
    decide, decide_removal, AccessRequest, ServiceSet, Outcome, RemovalOutcome, DecideOptions,
)


def _flag(r, **kw):
    for k, v in kw.items():
        setattr(r, k, v)
    return r


def _req(src, dst="Any", **kw):
    return AccessRequest([src], [dst], **kw)


# (id, op, rules, request, options, check) — op: "add" -> decide, "rem" -> decide_removal.
SCENARIOS = [
    # ---- ADD: reuse / widen / create -------------------------------------------------------------
    ("add-noop-exact", "add",
     [_rule("g", 4, "Accept", _host("10.1.2.250"), ANY, _app({"CNN"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is Outcome.NO_OP),
    ("add-widen-same-src-diff-app", "add",
     [_rule("fb", 4, "Accept", _host("10.1.2.250"), ANY, _app({"Facebook"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is Outcome.WIDEN and d.target_rule.uid == "fb" and d.widen_field == "service"),
    ("add-create-nothing-covers", "add",
     [_rule("fb", 4, "Accept", _host("10.9.9.9"), ANY, _app({"Facebook"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is Outcome.CREATE),
    ("add-create-above-covering-deny", "add",
     [_rule("dny", 3, "Drop", _host("10.1.2.250"), _host("9.9.9.9"), _tcp("443")), CLEANUP],
     _req("10.1.2.250/32", "9.9.9.9/32", protocol="tcp", ports="443"), None,
     lambda d: d.outcome is Outcome.CREATE and d.position == {"above": "dny"}),
    ("add-carveout-above-web-drop", "add",
     [_rule("sd", 3, "Drop", ANY, ANY, _tcp("443")), CLEANUP],
     _req("10.1.2.250/32", application="Facebook"), None,
     lambda d: d.outcome is Outcome.CREATE and d.position == {"above": "sd"}),
    # the USER's Issue-1 case: a Stealth 'Any->GW Drop' GENUINELY overlaps the request's Any destination
    # (Any superset-of GW), so widening the Facebook accept ABOVE it would let CNN->gateways bypass the
    # stealth. CREATE-below-the-stealth is the CORRECT least-privilege placement, NOT a bug.
    ("add-stealth-genuine-overlap-create-below", "add",
     [_rule("fb", 4, "Accept", _host("10.1.2.250"), ANY, _app({"Facebook"})),
      _flag(_rule("st", 9, "Drop", ANY, _host("10.1.2.1"), ServiceSet(any=True)), dst_approx=True), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is Outcome.CREATE and d.position != {"above": "fb"}),
    # GROUP B (fixed): a clean widen target ABOVE an interfering dynamic divert -> widen it, don't floor.
    ("add-widen-above-dynamic-divert", "add",
     [_rule("fb", 10, "Accept", _host("10.1.2.250"), ANY, _app({"Facebook"})),
      _flag(_rule("dl", 11, "Accept", ANY, ANY, ServiceSet(any=True)), dynamic_layer=True), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is Outcome.WIDEN and d.target_rule.uid == "fb"),
    ("add-disjoint-dynamic-ignored", "add",
     [_rule("fb", 10, "Accept", _host("10.1.2.250"), ANY, _app({"Facebook"})),
      _flag(_rule("dl", 11, "Accept", _net("192.168.0.0/24"), ANY, ServiceSet(any=True)), dynamic_layer=True), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is Outcome.WIDEN and d.target_rule.uid == "fb"),

    # ---- REMOVE: disable / deny / no-op / review -------------------------------------------------
    ("rem-disable-sole-exact", "rem",
     [_rule("g", 4, "Accept", _host("10.1.2.250"), ANY, _app({"CNN"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.DISABLE and d.target_rule.uid == "g"),
    ("rem-deny-broader", "rem",
     [_rule("b", 2, "Accept", _net("10.1.2.0/24"), ANY, _app({"CNN"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.DENY and d.position == {"above": "b"}),
    ("rem-noop-not-permitted", "rem",
     [_rule("o", 2, "Accept", _host("10.9.9.9"), ANY, _app({"CNN"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.NO_OP),
    ("rem-review-opaque-grant", "rem",
     [_flag(_rule("op", 2, "Accept", _host("10.1.2.250"), ANY, ServiceSet(complex=True)), svc_unknown=True), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.REVIEW),
    # GROUP A (fixed) — the USER's Issue-2: a CP-Updates accept (gateway src approx + updatable dst) ABOVE
    # the real grant is resolved-disjoint on source -> stepped over -> the real grant is DISABLEd (not REVIEW).
    ("rem-cpupd-above-grant-disable", "rem",
     [_flag(_rule("cp", 2, "Accept", _host("10.1.2.5"), _host("203.0.113.9"), _tcp("80,443")),
            src_approx=True, dst_unknown=True),
      _rule("cnn", 14, "Accept", _host("10.1.2.250"), ANY, _app({"CNN"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.DISABLE and d.target_rule.uid == "cnn"),
    # control: same rule BELOW the grant -> still DISABLE (the above/below symmetry must hold).
    ("rem-cpupd-below-grant-disable", "rem",
     [_rule("cnn", 4, "Accept", _host("10.1.2.250"), ANY, _app({"CNN"})),
      _flag(_rule("cp", 5, "Accept", _host("10.1.2.5"), _host("203.0.113.9"), _tcp("80,443")),
            src_approx=True, dst_unknown=True), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.DISABLE and d.target_rule.uid == "cnn"),
    # GROUP C (fixed under-removal) — a broad tcp/80,443 Accept on the SAME src+dst BELOW an app rule DOES
    # re-grant the web app (App Control over 443) -> must DENY (Drop-above), never a clean DISABLE.
    ("rem-svc-port-regrants-app-deny", "rem",
     [_rule("rfb", 8, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _app({"Facebook"})),
      _rule("rports", 9, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp("80,443")), CLEANUP],
     _req("10.0.0.5/32", "1.1.1.1/32", application="Facebook"), None,
     lambda d: d.outcome is RemovalOutcome.DENY),
    # control: a NetBIOS drop can't carry a web app -> resolved-disjoint -> doesn't block the disable.
    ("rem-netbios-disjoint-disable", "rem",
     [_rule("g", 4, "Accept", _host("10.1.2.250"), ANY, _app({"Facebook"})),
      _rule("nbt", 5, "Drop", ANY, ANY, ServiceSet(by_proto={"tcp": [(139, 139)], "udp": [(137, 138)]})), CLEANUP],
     _req("10.1.2.250/32", application="Facebook"), None,
     lambda d: d.outcome is RemovalOutcome.DISABLE and d.target_rule.uid == "g"),
    # dynamic layer in the path is SKIPPED -> the walk reaches the real grant (golden rule).
    ("rem-dynamic-skipped-to-grant", "rem",
     [_flag(_rule("dl", 1, "Accept", _net("10.1.2.0/24"), ANY, ServiceSet(any=True)), dynamic_layer=True),
      _rule("g", 2, "Accept", _host("10.1.2.250"), ANY, _app({"CNN"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.DISABLE and d.target_rule.uid == "g"),
    # dynamic layer BELOW a would-be-disable -> DENY (Drop-above) kept (the user's "keep DENY-safety" call).
    ("rem-dynamic-below-deny", "rem",
     [_rule("ex", 1, "Accept", _host("10.0.0.5"), _host("1.1.1.1"), _tcp("443")),
      _flag(_rule("dl", 2, "Accept", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True)), dynamic_layer=True),
      CLEANUP],
     _req("10.0.0.5/32", "1.1.1.1/32", protocol="tcp", ports="443"), None,
     lambda d: d.outcome is RemovalOutcome.DENY and d.position == {"above": "ex"}),
    # conditional DROP must not mask a re-granting accept under ignore_conditions.
    ("rem-conditional-drop-not-mask", "rem",
     [_rule("cd", 1, "Drop", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True), conditions=("VPN",)),
      _rule("ba", 2, "Accept", _net("10.0.0.0/24"), _host("1.1.1.1"), ServiceSet(any=True)), CLEANUP],
     _req("10.0.0.5/32", "1.1.1.1/32", protocol="tcp", ports="443"), DecideOptions(ignore_conditions=True),
     lambda d: d.outcome is RemovalOutcome.REVIEW),

    # ---- resolved-disjointness BOUNDARY guards (the exact above/below, disjoint/overlap, src-disjoint/src-
    #      overlap edges the QA reports pinned — _out_of_path must hold these) -----------------------------
    # a Stealth 'Any->GW Drop' (dst_approx) whose GW main IP is resolved-DISJOINT from the request dest is
    # stepped over -> the real grant is disabled (not a partial-drop REVIEW).
    ("rem-stealth-drop-disjoint-disable", "rem",
     [_flag(_rule("st", 2, "Drop", ANY, _host("10.1.2.1"), ServiceSet(any=True)), dst_approx=True),
      _rule("cnn", 5, "Accept", _host("10.1.2.250"), _host("172.16.5.10"), _tcp("443")), CLEANUP],
     _req("10.1.2.250/32", "172.16.5.10/32", protocol="tcp", ports="443"), None,
     lambda d: d.outcome is RemovalOutcome.DISABLE and d.target_rule.uid == "cnn"),
    # MUST STAY REVIEW: a CP-Updates rule whose SOURCE genuinely overlaps the request (src == the host) and
    # whose dst is updatable/unresolvable -> resolved-overlapping + opaque -> REVIEW (don't guess).
    ("rem-cpupd-src-overlaps-review", "rem",
     [_flag(_rule("cpo", 3, "Accept", _host("10.1.2.250"), _net("23.0.0.0/8"), _tcp("80,443")),
            dst_unknown=True, complex=True),
      _rule("cnn", 5, "Accept", _host("10.1.2.250"), ANY, _app({"CNN"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.REVIEW),
    # MUST STAY NO_OP: a resolved DROP that fully covers -> already denied, nothing to remove.
    ("rem-resolved-drop-covers-noop", "rem",
     [_rule("d", 2, "Drop", _host("10.1.2.250"), ANY, _app({"CNN"})), CLEANUP],
     _req("10.1.2.250/32", application="CNN"), None,
     lambda d: d.outcome is RemovalOutcome.NO_OP),
    # control for the under-removal guard: an http/https accept below on a DIFFERENT source is resolved-
    # disjoint on src -> NOT a re-granter -> the app rule is cleanly DISABLEd (the SVC-12 fix must not over-fire).
    ("rem-web-below-diff-src-disable", "rem",
     [_rule("rfb", 8, "Accept", _host("10.1.2.50"), _host("172.16.5.10"), _app({"Facebook"})),
      _rule("rw2", 9, "Accept", _host("10.9.9.9"), _host("172.16.5.10"), ServiceSet(by_proto={"tcp": [(80, 80), (443, 443)]})),
      CLEANUP],
     _req("10.1.2.50/32", "172.16.5.10/32", application="Facebook"), None,
     lambda d: d.outcome is RemovalOutcome.DISABLE and d.target_rule.uid == "rfb"),
    # ADD: a resolved-DISJOINT approx Stealth drop must NOT suppress a legitimate widen.
    ("add-stealth-disjoint-widen", "add",
     [_rule("tkt", 4, "Accept", _host("10.1.2.250"), _host("172.16.5.50"), _tcp("1433")),
      _flag(_rule("st", 10, "Drop", ANY, _host("192.0.2.1"), ServiceSet(any=True)), dst_approx=True), CLEANUP],
     _req("10.1.2.99/32", "172.16.5.50/32", protocol="tcp", ports="1433"), None,
     lambda d: d.outcome is Outcome.WIDEN and d.target_rule.uid == "tkt"),
    # ADD control: an approx Stealth drop whose dst OVERLAPS the request stays conservative (create, not
    # widen-above — its true reach may be wider, so don't leap above it).
    ("add-stealth-overlap-create", "add",
     [_rule("tkt", 4, "Accept", _host("10.1.2.250"), _host("172.16.5.50"), _tcp("1433")),
      _flag(_rule("st", 10, "Drop", ANY, _host("172.16.5.50"), ServiceSet(any=True)), dst_approx=True), CLEANUP],
     _req("10.1.2.99/32", "172.16.5.50/32", protocol="tcp", ports="1433"), None,
     lambda d: d.outcome is Outcome.CREATE),
]


@pytest.mark.parametrize("sid,op,rules,req,opts,check", SCENARIOS, ids=[s[0] for s in SCENARIOS])
def test_aa_scenario(sid, op, rules, req, opts, check):
    d = decide(req, rules, opts) if op == "add" else decide_removal(req, rules, opts)
    assert check(d), f"{sid}: unexpected {d.outcome.value} — {d.reason}"
