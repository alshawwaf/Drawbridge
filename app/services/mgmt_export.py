"""Turn a pulled Check Point policy (a layer's rulebase + the objects it references) into
Infrastructure-as-Code — **Terraform** (``CheckPointSW/checkpoint``), **Ansible**
(``check_point.mgmt``) and a **mgmt_cli** shell script — as a config *backup-as-code*.

Design notes (mirroring CP's own ExportImportPolicyPackage resilience):
  * **Never fail on an unknown object type.** Types we don't have a spec for are counted and listed
    under ``stats.skipped`` and annotated as comments, not dropped silently or crashed on.
  * **Predefined objects** (the "Check Point Data" domain — ``Any``, ``Original``, predefined
    services, the ``Accept``/``Drop`` actions, ``Log`` track …) exist on every SMS, so they are
    referenced **by name** and never re-emitted as resources.
  * **Order is preserved.** Sections and rules are emitted top→bottom and appended to the layer's
    bottom on restore; Terraform additionally gets a ``depends_on`` chain so ``apply`` keeps order.
  * Object↔object and rule→object references resolve to real Terraform resource addresses when the
    target is in the export set, so ``terraform apply`` builds the dependency graph correctly;
    Ansible / mgmt_cli reference by name (objects are created before the rules that use them).

These are pure functions over the bundle that ``mgmt_api.pull_for_export`` returns — no network — so
they are fully unit-tested without a live SMS.
"""
from __future__ import annotations

import re

# --- object type specs -----------------------------------------------------------------------
# Per CP object type: the Terraform resource, the Ansible module, the mgmt_cli object, and the
# fields to carry over as (cp-show-key, terraform-key, ansible-key, mgmt_cli-key, kind).
# kind: "scalar" (quoted), "int" (bare when numeric), "members" (list of object references).
OBJ_SPECS: dict[str, dict] = {
    "host": {"tf": "checkpoint_management_host", "ansible": "cp_mgmt_host", "cli": "host",
             "fields": [("ipv4-address", "ipv4_address", "ip_address", "ip-address", "scalar")]},
    "network": {"tf": "checkpoint_management_network", "ansible": "cp_mgmt_network", "cli": "network",
                "fields": [("subnet4", "subnet4", "subnet", "subnet4", "scalar"),
                           ("mask-length4", "mask_length4", "mask_length4", "mask-length4", "int")]},
    "address-range": {"tf": "checkpoint_management_address_range", "ansible": "cp_mgmt_address_range",
                      "cli": "address-range",
                      "fields": [("ipv4-address-first", "ipv4_address_first", "ip_address_first",
                                  "ip-address-first", "scalar"),
                                 ("ipv4-address-last", "ipv4_address_last", "ip_address_last",
                                  "ip-address-last", "scalar")]},
    "group": {"tf": "checkpoint_management_group", "ansible": "cp_mgmt_group", "cli": "group",
              "fields": [("members", "members", "members", "members", "members")]},
    "service-tcp": {"tf": "checkpoint_management_service_tcp", "ansible": "cp_mgmt_service_tcp",
                    "cli": "service-tcp", "fields": [("port", "port", "port", "port", "scalar")]},
    "service-udp": {"tf": "checkpoint_management_service_udp", "ansible": "cp_mgmt_service_udp",
                    "cli": "service-udp", "fields": [("port", "port", "port", "port", "scalar")]},
    "service-icmp": {"tf": "checkpoint_management_service_icmp", "ansible": "cp_mgmt_service_icmp",
                     "cli": "service-icmp",
                     "fields": [("icmp-type", "icmp_type", "icmp_type", "icmp-type", "int"),
                                ("icmp-code", "icmp_code", "icmp_code", "icmp-code", "int")]},
    "service-other": {"tf": "checkpoint_management_service_other", "ansible": "cp_mgmt_service_other",
                      "cli": "service-other",
                      "fields": [("ip-protocol", "ip_protocol", "ip_protocol", "ip-protocol", "int")]},
    "service-group": {"tf": "checkpoint_management_service_group", "ansible": "cp_mgmt_service_group",
                      "cli": "service-group",
                      "fields": [("members", "members", "members", "members", "members")]},
    "access-role": {"tf": "checkpoint_management_access_role", "ansible": "cp_mgmt_access_role",
                    "cli": "access-role", "fields": [],
                    "note": "access-role members (networks / users / machines) are not exported — "
                            "re-add them before applying."},
}

# Object types that are part of every management database (predefined) — referenced, never emitted.
_PREDEFINED_TYPES = {"CpmiAnyObject", "RulebaseAction", "Track", "Global",
                     "CpmiGatewayPlain", "Track-Object"}
_PREDEFINED_NAMES = {"Any", "Original", "None", "Policy Targets", "All_Internet"}


def is_predefined(obj: dict) -> bool:
    """Predefined objects live in the read-only "Check Point Data" domain (or are action/track
    pseudo-objects). They exist on every SMS, so we reference them by name and never re-create them."""
    if (((obj.get("domain") or {}).get("domain-type")) or "") == "data domain":
        return True
    if obj.get("type") in _PREDEFINED_TYPES:
        return True
    return obj.get("name") in _PREDEFINED_NAMES


# --- small helpers ---------------------------------------------------------------------------

def slugify(name: str, used: set[str]) -> str:
    """A unique, valid Terraform/Ansible identifier for an object name."""
    s = re.sub(r"[^0-9A-Za-z_]", "_", (name or "").strip())
    s = re.sub(r"_+", "_", s).strip("_").lower() or "obj"
    if s[0].isdigit():
        s = "n_" + s
    cand, i = s, 2
    while cand in used:
        cand, i = f"{s}_{i}", i + 1
    used.add(cand)
    return cand


def _q(s) -> str:
    """Double-quoted, escaped, single-line string (shared by HCL / YAML / shell-arg contexts)."""
    text = re.sub(r"\s*\n\s*", " ", str(s)).replace("\\", "\\\\").replace('"', '\\"')
    return f'"{text}"'


def _is_int(v) -> bool:
    return str(v).lstrip("-").isdigit()


def _member_names(obj: dict) -> list[str]:
    out = []
    for m in obj.get("members") or []:
        out.append(m.get("name") or m.get("uid") if isinstance(m, dict) else m)
    return [m for m in out if m]


def _cell(values: list[str]) -> list[str]:
    """An empty rule cell means 'Any' in Check Point."""
    return values if values else ["Any"]


# --- public entry point ----------------------------------------------------------------------

def generate(bundle: dict) -> dict:
    """Render a pulled-policy bundle to all three targets.

    bundle = {layer, rules (structured rows: section/rule/other), objects_by_type {type: [obj]}}.
    Returns {layer, terraform, ansible, mgmt_cli, stats}.
    """
    layer = bundle.get("layer", "")
    rules = [dict(r) for r in bundle.get("rules", [])]   # copy — we annotate with slugs
    objects_by_type: dict[str, list] = bundle.get("objects_by_type", {})

    used: set[str] = set()
    emit: list[dict] = []           # objects we can render, in a stable order
    skipped: dict[str, int] = {}
    ref_map: dict[str, str] = {}    # object name -> terraform address (for dependency wiring)

    # Objects first: assign slugs + build the name→TF-address map so members/cells can reference.
    for cp_type in sorted(objects_by_type):
        spec = OBJ_SPECS.get(cp_type)
        objs = objects_by_type[cp_type]
        if not spec:
            skipped[cp_type] = skipped.get(cp_type, 0) + len(objs)
            continue
        for o in objs:
            slug = slugify(o.get("name", ""), used)
            emit.append({"cp_type": cp_type, "spec": spec, "obj": o, "slug": slug})
            if o.get("name"):
                ref_map[o["name"]] = f'{spec["tf"]}.{slug}.name'

    # Then sections + rules get their own slugs (kept distinct from object slugs).
    for row in rules:
        if row.get("kind") == "section":
            row["_slug"] = slugify("sec_" + (row.get("name") or "section"), used)
        elif row.get("kind") == "rule":
            label = row.get("name") or f"rule_{row.get('number') or ''}"
            row["_slug"] = slugify("rule_" + label, used)

    stats = {
        "objects": len(emit),
        "rules": sum(1 for r in rules if r.get("kind") == "rule"),
        "sections": sum(1 for r in rules if r.get("kind") == "section"),
        "skipped": skipped,
    }
    return {
        "layer": layer,
        "terraform": _render_terraform(layer, emit, rules, ref_map, skipped),
        "ansible": _render_ansible(layer, emit, rules, skipped),
        "mgmt_cli": _render_mgmt_cli(layer, emit, rules, skipped),
        "stats": stats,
    }


# --- Terraform (CheckPointSW/checkpoint) ------------------------------------------------------

def _tf_ref(name: str, ref_map: dict[str, str]) -> str:
    """A resource reference when the target is in our export set, else a quoted literal name."""
    return ref_map[name] if name in ref_map else _q(name)


def _render_terraform(layer, emit, rules, ref_map, skipped) -> str:
    L = [f"# Terraform export of Check Point access layer \"{layer}\".",
         "# Provider: CheckPointSW/checkpoint. Configure the provider with your SMS credentials,",
         "# then `terraform init && terraform apply`. Restore into an EMPTY layer to reproduce order.",
         "",
         "terraform {",
         "  required_providers {",
         "    checkpoint = {",
         '      source = "CheckPointSW/checkpoint"',
         "    }",
         "  }",
         "}",
         ""]
    if skipped:
        L.append(_skip_banner(skipped, "#"))
        L.append("")

    for e in emit:
        spec, o, slug = e["spec"], e["obj"], e["slug"]
        L.append(f'resource "{spec["tf"]}" "{slug}" {{')
        L.append(f'  name = {_q(o.get("name", ""))}')
        for cpk, tfk, _ak, _clk, kind in spec["fields"]:
            v = o.get(cpk)
            if v in (None, ""):
                continue
            if kind == "members":
                refs = ", ".join(_tf_ref(m, ref_map) for m in _member_names(o))
                L.append(f"  {tfk} = [{refs}]")
            elif kind == "int" and _is_int(v):
                L.append(f"  {tfk} = {v}")
            else:
                L.append(f"  {tfk} = {_q(v)}")
        if o.get("comments"):
            L.append(f'  comments = {_q(o["comments"])}')
        if spec.get("note"):
            L.append(f'  # NOTE: {spec["note"]}')
        L.append("}")
        L.append("")

    prev_addr = None
    for row in rules:
        kind = row.get("kind")
        if kind == "section":
            addr = f'checkpoint_management_access_section.{row["_slug"]}'
            L.append(f'resource "checkpoint_management_access_section" "{row["_slug"]}" {{')
            L.append(f'  name = {_q(row.get("name") or "Section")}')
            L.append(f"  layer = {_q(layer)}")
            L.append('  position = "bottom"')
            if prev_addr:
                L.append(f"  depends_on = [{prev_addr}]")
            L.append("}")
            L.append("")
            prev_addr = addr
        elif kind == "rule":
            addr = f'checkpoint_management_access_rule.{row["_slug"]}'
            L.append(f'resource "checkpoint_management_access_rule" "{row["_slug"]}" {{')
            L.append(f'  name = {_q(row.get("name") or "")}')
            L.append(f"  layer = {_q(layer)}")
            L.append('  position = "bottom"')
            L.append("  source = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in _cell(row.get("source", []))))
            L.append("  destination = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in _cell(row.get("destination", []))))
            L.append("  service = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in _cell(row.get("service", []))))
            if row.get("vpn"):
                L.append("  vpn = [%s]" % ", ".join(_tf_ref(n, ref_map) for n in row["vpn"]))
            L.append(f'  action = {_q(row.get("action") or "Drop")}')
            if row.get("track"):
                L.append(f'  track {{\n    type = {_q(row["track"])}\n  }}')
            L.append(f'  enabled = {"true" if row.get("enabled", True) else "false"}')
            for neg in ("source_negate", "destination_negate", "service_negate"):
                if row.get(neg):
                    L.append(f"  {neg} = true")
            if row.get("comments"):
                L.append(f'  comments = {_q(row["comments"])}')
            if prev_addr:
                L.append(f"  depends_on = [{prev_addr}]")
            L.append("}")
            L.append("")
            prev_addr = addr
        else:
            L.append(f'# unsupported rulebase item: {row.get("type", "unknown")} {row.get("name", "")}')
            L.append("")
    return "\n".join(L).rstrip() + "\n"


# --- Ansible (check_point.mgmt) ---------------------------------------------------------------

def _yaml_list(values: list[str]) -> str:
    return "[" + ", ".join(_q(v) for v in values) + "]"


def _render_ansible(layer, emit, rules, skipped) -> str:
    L = [f'# Ansible export of Check Point access layer "{layer}".',
         "# Collection: check_point.mgmt. Run against a host configured for the Management API.",
         "# Restore into an EMPTY layer to reproduce rule order."]
    if skipped:
        L.append(_skip_banner(skipped, "#"))
    L += ["---",
          f'- name: Restore Check Point policy — layer "{layer}"',
          "  hosts: localhost",
          "  gather_facts: false",
          "  tasks:"]

    for e in emit:
        spec, o = e["spec"], e["obj"]
        L.append(f'    - name: Add {spec["cli"]} {o.get("name", "")}')
        L.append(f'      check_point.mgmt.{spec["ansible"]}:')
        L.append(f'        name: {_q(o.get("name", ""))}')
        for cpk, _tfk, ak, _clk, kind in spec["fields"]:
            v = o.get(cpk)
            if v in (None, ""):
                continue
            if kind == "members":
                L.append(f"        {ak}: {_yaml_list(_member_names(o))}")
            elif kind == "int" and _is_int(v):
                L.append(f"        {ak}: {v}")
            else:
                L.append(f"        {ak}: {_q(v)}")
        if o.get("comments"):
            L.append(f'        comments: {_q(o["comments"])}')
        L.append("        state: present")
        if spec.get("note"):
            L.append(f'      # NOTE: {spec["note"]}')

    for row in rules:
        kind = row.get("kind")
        if kind == "section":
            L.append(f'    - name: Add section {row.get("name") or "Section"}')
            L.append("      check_point.mgmt.cp_mgmt_access_section:")
            L.append(f"        layer: {_q(layer)}")
            L.append("        position: bottom")
            L.append(f'        name: {_q(row.get("name") or "Section")}')
            L.append("        state: present")
        elif kind == "rule":
            L.append(f'    - name: Add rule {row.get("name") or row.get("number") or ""}')
            L.append("      check_point.mgmt.cp_mgmt_access_rule:")
            L.append(f"        layer: {_q(layer)}")
            L.append("        position: bottom")
            L.append(f'        name: {_q(row.get("name") or "")}')
            L.append(f"        source: {_yaml_list(_cell(row.get('source', [])))}")
            L.append(f"        destination: {_yaml_list(_cell(row.get('destination', [])))}")
            L.append(f"        service: {_yaml_list(_cell(row.get('service', [])))}")
            if row.get("vpn"):
                L.append(f"        vpn: {_yaml_list(row['vpn'])}")
            L.append(f'        action: {_q(row.get("action") or "Drop")}')
            if row.get("track"):
                L.append("        track:")
                L.append(f'          type: {_q(row["track"])}')
            L.append(f'        enabled: {"true" if row.get("enabled", True) else "false"}')
            for neg, key in (("source_negate", "source-negate"), ("destination_negate", "destination-negate"),
                             ("service_negate", "service-negate")):
                if row.get(neg):
                    L.append(f"        {key}: true")
            if row.get("comments"):
                L.append(f'        comments: {_q(row["comments"])}')
            L.append("        state: present")
        else:
            L.append(f'    # unsupported rulebase item: {row.get("type", "unknown")} {row.get("name", "")}')

    L += ["    - name: Publish",
          "      check_point.mgmt.cp_mgmt_publish:"]
    return "\n".join(L).rstrip() + "\n"


# --- mgmt_cli script --------------------------------------------------------------------------

def _cli_list(prefix: str, values: list[str]) -> str:
    return " ".join(f"{prefix}.{i} {_q(v)}" for i, v in enumerate(values, start=1))


def _render_mgmt_cli(layer, emit, rules, skipped) -> str:
    L = ["#!/bin/bash",
         f'# mgmt_cli export of Check Point access layer "{layer}".',
         "# 1) Log in (writes the session id to id.txt — fill in your host/credentials):",
         '#    mgmt_cli login user "admin" password "PASSWORD" management "MGMT_IP" > id.txt',
         "#    (add: domain \"DOMAIN\" for an MDS / CMA)",
         "# 2) Run this script. 3) It publishes and logs out at the end.",
         "set -e", ""]
    if skipped:
        L.append(_skip_banner(skipped, "#"))
        L.append("")

    def add(obj_kind: str, args: str) -> str:
        return f'mgmt_cli add {obj_kind} {args} --ignore-warnings true -s id.txt'

    for e in emit:
        spec, o = e["spec"], e["obj"]
        parts = [f'name {_q(o.get("name", ""))}']
        for cpk, _tfk, _ak, clk, kind in spec["fields"]:
            v = o.get(cpk)
            if v in (None, ""):
                continue
            if kind == "members":
                ml = _cli_list("members", _member_names(o))
                if ml:
                    parts.append(ml)
            elif kind == "int" and _is_int(v):
                parts.append(f"{clk} {v}")
            else:
                parts.append(f"{clk} {_q(v)}")
        if o.get("comments"):
            parts.append(f'comments {_q(o["comments"])}')
        L.append(add(spec["cli"], " ".join(parts)))
        if spec.get("note"):
            L.append(f'# NOTE: {spec["note"]}')

    for row in rules:
        kind = row.get("kind")
        if kind == "section":
            L.append(add("access-section",
                         f'layer {_q(layer)} position bottom name {_q(row.get("name") or "Section")}'))
        elif kind == "rule":
            parts = [f"layer {_q(layer)}", "position bottom", f'name {_q(row.get("name") or "")}',
                     _cli_list("source", _cell(row.get("source", []))),
                     _cli_list("destination", _cell(row.get("destination", []))),
                     _cli_list("service", _cell(row.get("service", []))),
                     f'action {_q(row.get("action") or "Drop")}']
            if row.get("vpn"):
                parts.append(_cli_list("vpn", row["vpn"]))
            if row.get("track"):
                parts.append(f'track-settings.type {_q(row["track"])}')
            parts.append(f'enabled {"true" if row.get("enabled", True) else "false"}')
            for neg, key in (("source_negate", "source-negate"), ("destination_negate", "destination-negate"),
                             ("service_negate", "service-negate")):
                if row.get(neg):
                    parts.append(f"{key} true")
            if row.get("comments"):
                parts.append(f'comments {_q(row["comments"])}')
            L.append(add("access-rule", " ".join(parts)))
        else:
            L.append(f'# unsupported rulebase item: {row.get("type", "unknown")} {row.get("name", "")}')

    L += ["", "mgmt_cli publish -s id.txt", "mgmt_cli logout -s id.txt"]
    return "\n".join(L).rstrip() + "\n"


def _skip_banner(skipped: dict[str, int], comment: str) -> str:
    lines = [f"{comment} Skipped {sum(skipped.values())} object(s) of unsupported type(s) "
             "(no IaC mapping yet):"]
    for t in sorted(skipped):
        lines.append(f"{comment}   - {t}: {skipped[t]}")
    return "\n".join(lines)
