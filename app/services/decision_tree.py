"""The access-automation decision tree as DATA, plus portable diagram exporters.

ONE source of truth for the visual — the same first-match flow ``access_automation.decide()`` implements,
rendered into the formats a customer's own tools open, so the diagram can never drift from the engine:

  * Mermaid (.mmd)      — GitHub / GitLab / Obsidian / VS Code / mermaid.live, and **draw.io imports it**
  * diagrams.net (.drawio / mxGraph XML) — opens + edits in app.diagrams.net, and exports to
                          **Microsoft Visio (.vsdx)**, PDF, PNG, SVG from there
  * Graphviz (.dot)     — every open-source graph viewer (xdot, Graphviz, VS Code, …)

The on-page view renders this same Mermaid source client-side, so editing the tree means editing this
one file. Keep the NODES/EDGES below in lock-step with decide()."""
from __future__ import annotations

from dataclasses import dataclass
from xml.sax.saxutils import escape as _xescape


@dataclass(frozen=True)
class Node:
    id: str
    label: str
    sub: str
    kind: str        # start | process | decision | review | noop | widen | create
    x: int           # layout coords (used by the .drawio exporter; Mermaid/DOT auto-lay-out)
    y: int
    w: int = 250
    h: int = 64


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    label: str = ""


# The tree — mirrors decide(): guard (unsupported/malformed) -> resolve each cell (exact/approx/opaque)
# -> already permitted? -> denied/unverifiable? -> two cells equal? -> else create.
NODES: list[Node] = [
    Node("req", "Access request", "source · destination · service / app", "start", 60, 20),
    Node("unsup", "Unsupported / malformed?", "IPv6 · no concrete service", "decision", 60, 130),
    Node("revU", "Review", "unsupported / malformed", "review", 420, 130, 240),
    Node("resolve", "Resolve each cell to its real extent",
         "exact: host / network / range / group  ·  approx: gateway / cluster / mgmt  ·  opaque → review",
         "process", 60, 240, 250, 84),
    Node("revO", "Review", "object with no IP extent", "review", 420, 252, 240),
    Node("perm", "Already permitted?", "first reachable Accept that covers it", "decision", 60, 374),
    Node("noop", "No-op", "already allowed — attach the rule", "noop", 420, 374, 240),
    Node("deny", "Denied or can't verify in path?",
         "explicit / partial / approx drop · negate · conditional", "decision", 60, 484, 250, 68),
    Node("revD", "Review", "a deny, or scope we can't verify", "review", 420, 486, 240),
    Node("widen", "Two cells equal the request?", "widen the third — add to that cell", "decision",
         60, 598, 250, 68),
    Node("doWiden", "Widen the rule", "add the differing source / destination / service", "widen",
         420, 600, 240),
    Node("create", "Create least-privilege rule", "above the cleanup / a blocking drop", "create", 60, 712),
]

EDGES: list[Edge] = [
    Edge("req", "unsup"),
    Edge("unsup", "revU", "yes"), Edge("unsup", "resolve", "no"),
    Edge("resolve", "revO", "opaque object"), Edge("resolve", "perm", "resolved"),
    Edge("perm", "noop", "yes"), Edge("perm", "deny", "no"),
    Edge("deny", "revD", "yes"), Edge("deny", "widen", "no"),
    Edge("widen", "doWiden", "yes"), Edge("widen", "create", "no"),
]

# kind -> (fill, stroke, font) — one palette every renderer shares, so .mmd/.drawio/.dot look the same.
# Hierarchy: the process/decision steps are quiet (light slate, dark text); the four OUTCOMES are bold
# solid badges (white text) so the eye lands on what the engine actually does — and the colours map to
# the legend: green = no-op, blue = widen, amber = create, rose = review.
PALETTE: dict[str, tuple[str, str, str]] = {
    "start":    ("#f1f5fb", "#cbd5e6", "#243244"),   # quiet entry
    "process":  ("#eef2f9", "#cbd5e6", "#243244"),   # quiet step
    "decision": ("#e2e8f2", "#94a3b8", "#1e293b"),   # slightly stronger outline — reads as a gate
    "review":   ("#e11d48", "#be123c", "#ffffff"),   # rose-600  — human decides
    "noop":     ("#0f9d6e", "#0b7d58", "#ffffff"),   # emerald   — already allowed
    "widen":    ("#2563eb", "#1d4ed8", "#ffffff"),   # blue      — extend a rule
    "create":   ("#e08600", "#b45309", "#ffffff"),   # amber     — new rule
}


# --- Mermaid -------------------------------------------------------------------------------------
# shape delimiters per kind: stadium for start, hexagons for decisions, rounded rects for the rest.
_MM_SHAPE = {"start": ('(["', '"])'), "process": ('["', '"]'), "decision": ('{{"', '"}}'),
             "review": ('("', '")'), "noop": ('("', '")'), "widen": ('("', '")'), "create": ('("', '")')}


def _mm_text(n: Node) -> str:
    txt = n.label + (f"<br/>{n.sub}" if n.sub else "")
    return txt.replace('"', "&quot;")


def to_mermaid() -> str:
    out = ["flowchart TD"]
    for n in NODES:
        o, c = _MM_SHAPE[n.kind]
        out.append(f"  {n.id}{o}{_mm_text(n)}{c}")
    out.append("")
    for e in EDGES:
        arrow = f" -->|{e.label}| " if e.label else " --> "
        out.append(f"  {e.src}{arrow}{e.dst}")
    out.append("")
    for kind, (fill, stroke, font) in PALETTE.items():
        out.append(f"  classDef {kind} fill:{fill},stroke:{stroke},color:{font},stroke-width:1px;")
    grouped: dict[str, list[str]] = {}
    for n in NODES:
        grouped.setdefault(n.kind, []).append(n.id)
    for kind, ids in grouped.items():
        out.append(f"  class {','.join(ids)} {kind};")
    return "\n".join(out)


# --- diagrams.net (.drawio / mxGraph XML) --------------------------------------------------------
def _attr(s: str) -> str:
    return _xescape(s, {'"': "&quot;"})


def _drawio_value(n: Node) -> str:
    # html=1 cell value: bold title + a smaller, muted sub-line. Escaped for the XML attribute.
    html = f"<b>{_xescape(n.label)}</b>"
    if n.sub:
        html += f'<br><span style="font-size:10px;color:#5b6573;">{_xescape(n.sub)}</span>'
    return _attr(html)


def to_drawio() -> str:
    cells: list[str] = []
    for n in NODES:
        fill, stroke, font = PALETTE[n.kind]
        shape = "rhombus;" if n.kind == "decision" else "rounded=1;"
        style = (f"{shape}whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};"
                 f"fontColor={font};align=center;verticalAlign=middle;spacing=6;arcSize=12;")
        cells.append(
            f'<mxCell id="{n.id}" value="{_drawio_value(n)}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{n.x}" y="{n.y}" width="{n.w}" height="{n.h}" as="geometry"/></mxCell>')
    for i, e in enumerate(EDGES):
        style = ("edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;endArrow=block;endFill=1;"
                 "strokeColor=#8893a5;fontColor=#5b6573;fontSize=10;")
        cells.append(
            f'<mxCell id="e{i}" value="{_attr(e.label)}" style="{style}" edge="1" parent="1" '
            f'source="{e.src}" target="{e.dst}"><mxGeometry relative="1" as="geometry"/></mxCell>')
    body = "".join(cells)
    return (
        '<mxfile host="Drawbridge" type="device">'
        '<diagram id="decision-tree" name="Access automation decision tree">'
        '<mxGraphModel dx="900" dy="900" grid="0" gridSize="10" guides="1" tooltips="1" connect="1" '
        'arrows="1" fold="1" page="1" pageScale="1" pageWidth="850" pageHeight="1169" math="0" shadow="0">'
        f'<root><mxCell id="0"/><mxCell id="1" parent="0"/>{body}</root>'
        '</mxGraphModel></diagram></mxfile>')


# --- Graphviz (.dot) -----------------------------------------------------------------------------
def to_dot() -> str:
    out = ["digraph decision {", "  rankdir=TB;",
           '  node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, margin="0.14,0.07"];',
           '  edge [fontname="Helvetica", fontsize=9, color="#8893a5", fontcolor="#5b6573"];']
    for n in NODES:
        fill, stroke, font = PALETTE[n.kind]
        shape = "diamond" if n.kind == "decision" else "box"
        label = (n.label + (f"\\n{n.sub}" if n.sub else "")).replace('"', '\\"')
        out.append(f'  {n.id} [label="{label}", shape={shape}, fillcolor="{fill}", color="{stroke}", '
                   f'fontcolor="{font}"];')
    for e in EDGES:
        lbl = f' [label="{e.label}"]' if e.label else ""
        out.append(f"  {e.src} -> {e.dst}{lbl};")
    out.append("}")
    return "\n".join(out)


RENDERERS = {
    "drawio": (to_drawio, "application/xml; charset=utf-8", "drawio"),
    "mmd":    (to_mermaid, "text/plain; charset=utf-8", "mmd"),
    "dot":    (to_dot, "text/vnd.graphviz; charset=utf-8", "dot"),
}
