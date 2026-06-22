"""The decision-tree diagram exporters: structurally complete + valid Mermaid / .drawio / DOT,
and KEPT IN LOCK-STEP with the engine (the sync guards below go red if decide() grows an outcome or
the inline-layer / automation-mode branches lose their visual representation)."""
import xml.etree.ElementTree as ET

from app.services import decision_tree as dt
from app.services.access_automation import Outcome

# every engine Outcome must map to a tree node KIND (keyed on kind, not id: REVIEW has several leaves)
_OUTCOME_KIND = {Outcome.NO_OP: "noop", Outcome.WIDEN: "widen", Outcome.CREATE: "create",
                 Outcome.REVIEW: "review"}


def test_edges_reference_real_nodes_and_outcomes_present():
    ids = {n.id for n in dt.NODES}
    for e in dt.EDGES:
        assert e.src in ids and e.dst in ids, (e.src, e.dst)
    kinds = {n.kind for n in dt.NODES}
    assert {"review", "noop", "widen", "create", "decision", "start", "process"} <= kinds


def test_mermaid_is_well_formed():
    m = dt.to_mermaid()
    assert m.startswith("%%{init:") and "flowchart TD" in m and '"theme":"base"' in m   # self-themed
    assert dt.to_mermaid(dark=True) != m                                       # dark variant differs
    for n in dt.NODES:
        assert f"  {n.id}" in m                      # every node declared
    assert "-->|yes|" in m and "-->|no|" in m         # labelled branches
    assert "classDef review" in m and "class " in m   # styling applied
    # the resolution sub-step is spelled out in the resolve node
    assert "exact" in m and "approx" in m and "opaque" in m


def test_drawio_is_valid_xml_with_every_node_and_edge():
    x = dt.to_drawio()
    root = ET.fromstring(x)                            # must parse — malformed XML would raise
    assert root.tag == "mxfile"
    cells = {c.get("id") for c in root.iter("mxCell")}
    for n in dt.NODES:
        assert n.id in cells, n.id
    edge_cells = [c for c in root.iter("mxCell") if c.get("edge") == "1"]
    assert len(edge_cells) == len(dt.EDGES)
    # geometry present on a vertex
    v = next(c for c in root.iter("mxCell") if c.get("id") == "create")
    assert v.find("mxGeometry") is not None


def test_dot_is_well_formed():
    d = dt.to_dot()
    assert d.startswith("digraph decision {") and d.rstrip().endswith("}")
    assert "->" in d
    for n in dt.NODES:
        assert f"  {n.id} [" in d


def test_renderers_registry():
    assert set(dt.RENDERERS) == {"drawio", "mmd", "dot"}
    for fn, ctype, ext in dt.RENDERERS.values():
        assert callable(fn) and ctype and ext


# --- sync guards: the visual can't silently drift from decide() ----------------------------------
def test_every_engine_outcome_maps_to_a_tree_node_kind():
    # a NEW or renamed Outcome forces an update here (and a matching node) -> the suite goes red
    assert set(_OUTCOME_KIND) == set(Outcome)
    kinds = {n.kind for n in dt.NODES}
    for outcome, kind in _OUTCOME_KIND.items():
        assert kind in kinds, f"no tree node represents Outcome.{outcome.name}"
    # reverse: no orphan outcome-leaf kind left behind after an outcome is removed
    assert (kinds & {"noop", "widen", "create", "review"}) == set(_OUTCOME_KIND.values())


def test_all_nodes_reachable_from_a_single_start():
    starts = [n.id for n in dt.NODES if n.kind == "start"]
    assert len(starts) == 1, "the collapse BFS + the flow both need exactly one start node"
    adj: dict = {}
    for e in dt.EDGES:
        adj.setdefault(e.src, []).append(e.dst)
    seen, stack = set(), [starts[0]]
    while stack:
        x = stack.pop()
        if x in seen:
            continue
        seen.add(x)
        stack += adj.get(x, [])
    assert seen == {n.id for n in dt.NODES}, "node unreachable from start (orphaned in the diagram)"
    dsts = {e.dst for e in dt.EDGES}
    for n in dt.NODES:                                  # no drawn-but-unwired outcome leaf
        if n.kind in ("noop", "widen", "create", "review"):
            assert n.id in dsts, f"{n.id} is never reached by an edge"


def test_default_collapsed_view_cuts_at_bfs_depth():
    dv = dt.default_visible()
    allids = {n.id for n in dt.NODES}
    assert dv < allids, "nothing is collapsed — the depth cut is missing"
    depth = dt._bfs_depth()
    assert dv == {n.id for n in dt.NODES if depth[n.id] <= dt.DEFAULT_DEPTH}
    assert {"req", "unsup", "resolve"} <= dv                              # the top levels show
    assert not ({"create", "noop", "inline", "recurse", "opts"} & dv)    # deeper nodes are behind '+ more'


def test_bfs_depth_root_is_zero_and_all_reachable():
    depth = dt._bfs_depth()
    assert depth["req"] == 0 and all(d >= 0 for d in depth.values())
    assert set(depth) == {n.id for n in dt.NODES}                         # every node got a depth


def test_to_mermaid_visible_subset_filters_nodes_and_edges():
    dv = dt.default_visible()
    sub = dt.to_mermaid(dark=True, visible_ids=dv)
    assert "  inline" not in sub and "  recurse" not in sub              # collapsed nodes absent
    assert "applies an inline layer" not in sub                         # edge with a hidden endpoint dropped
    full = dt.to_mermaid(dark=True)
    assert "  recurse" in full and "applies an inline layer" in full    # the WHOLE tree (download) keeps all
    # subset output is still valid Mermaid in the SAME format
    assert sub.startswith("%%{init:") and "flowchart TD" in sub and "classDef review" in sub


def test_to_graph_is_client_consumable_and_matches_mermaid():
    g = dt.to_graph()
    assert g["start"] == "req" and g["default_depth"] == dt.DEFAULT_DEPTH
    assert {n["id"] for n in g["nodes"]} == {n.id for n in dt.NODES}
    assert all(set(n) >= {"id", "kind", "depth", "mm"} for n in g["nodes"])
    assert {(e["src"], e["dst"]) for e in g["edges"]} == {(e.src, e.dst) for e in dt.EDGES}
    for theme in ("dark", "light"):
        assert g["themes"][theme]["init"].startswith("%%{init:") and g["themes"][theme]["classDefs"]
    # the pre-formatted node line is byte-identical to what to_mermaid emits (no JS/Python format drift)
    full = dt.to_mermaid(dark=True)
    for n in g["nodes"]:
        assert ("  " + n["mm"]) in full


def test_inline_layer_recursion_and_automation_modes_are_drawn():
    # guards the two engine features shipped alongside this: they must stay represented in the visual
    ids = {n.id for n in dt.NODES}
    assert {"inline", "recurse", "inlineEnd", "opts"} <= ids
    edges = {(e.src, e.dst) for e in dt.EDGES}
    assert ("resolve", "inline") in edges                               # inline branch wired off resolve
    assert ("inline", "recurse") in edges                               # the recursion step
    assert ("inlineEnd", "inCreate") in edges and ("inlineEnd", "inNoop") in edges   # drop / accept cleanup
    assert ("opts", "odCreate") in edges                                # override-deny -> create above the deny
    inline_end = next(n for n in dt.NODES if n.id == "inlineEnd")
    assert "cleanup" in inline_end.label.lower()


def test_detail_branch_is_self_contained_no_cross_edges():
    # the inline-layer + automation-mode detail must terminate in its OWN leaves, never draw an edge back
    # to a CORE (level-0) leaf — those cross-edges were what tangled the expanded diagram.
    level = {n.id: n.level for n in dt.NODES}
    for e in dt.EDGES:
        if level.get(e.src, 0) >= 1:                  # an edge leaving a detail node...
            assert level.get(e.dst, 0) >= 1, f"detail edge {e.src}->{e.dst} reaches a core node"
