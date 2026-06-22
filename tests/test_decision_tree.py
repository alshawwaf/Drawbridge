"""The decision-tree diagram exporters: structurally complete + valid Mermaid / .drawio / DOT."""
import xml.etree.ElementTree as ET

from app.services import decision_tree as dt


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
