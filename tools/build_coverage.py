#!/usr/bin/env python3
"""Generate compact, versioned **coverage artifacts** from the Check Point OpenAPI specs.

For each API version it emits one JSON the portal bundles + serves on /coverage:
every object/command, its full documented field set (with type / enum / required), a ready-to-run
**web_api JSON example**, and per-field **API / Terraform / Ansible** support so the page can show a
colour-coded 3-way diff. TF/Ansible support is derived from the API schema + the documented
provider/collection divergences (recorded in TOOL_VERSIONS) — the web_api side is authoritative.

Source: the user's CP-Docs-To-Swagger specs. Default reads the local processed tree; pass --spec to
point elsewhere (a path or, for the in-app "check for updates", a URL the caller pre-downloads).

Usage:
    python tools/build_coverage.py                 # latest management + gaia → app/data/coverage/
    python tools/build_coverage.py --api management --version v2.0.1 --spec /path/openapi.json
"""
from __future__ import annotations

import argparse
import json
import os
import re

SPEC_ROOT = "/Users/khalid/Desktop/CP-Docs-To-Swagger/data/processed"
OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "coverage_data")

TOOL_VERSIONS = {
    "terraform": "CheckPointSW/checkpoint v3.2.0",
    "ansible_mgmt": "check_point.mgmt",
    "ansible_gaia": "check_point.gaia",
}

# Request-time flags that are NOT stored object fields — shown greyed, excluded from the support diff.
REQUEST_ONLY = {"ignore-warnings", "ignore-errors", "set-if-exists", "details-level"}

# Terraform field-level omissions vs the API (documented divergences from the research).
TF_OMIT_FIELDS = {"groups", "ip-address", "subnet", "mask-length", "subnet-mask", "service-resource"}
# Objects that have NO Terraform resource / NO Ansible module (object-level gaps).
TF_MISSING_OBJECTS: set[str] = set()
ANSIBLE_MISSING_OBJECTS = {"service-gtp", "opsec-application", "server-certificate",
                           "vmware-data-center-server", "aws-data-center-server", "azure-data-center-server"}


def _resolve(schema, spec, seen=None):
    seen = seen or set()
    while isinstance(schema, dict) and "$ref" in schema:
        ref = schema["$ref"]
        if ref in seen:
            return {}
        seen.add(ref)
        node = spec
        for part in ref.lstrip("#/").split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        schema = node
    return schema if isinstance(schema, dict) else {}


def _request_schema(spec, path):
    op = (spec.get("paths", {}).get(path, {}) or {}).get("post", {})
    return ((op.get("requestBody", {}) or {}).get("content", {}) or {}).get("application/json", {}).get("schema", {})


def _properties(schema, spec):
    """Flatten a request schema (resolving $ref + merging allOf) to {name: field-schema}."""
    out: dict = {}

    def walk(s):
        s = _resolve(s, spec)
        for sub in s.get("allOf", []) or []:
            walk(sub)
        for k, v in (s.get("properties") or {}).items():
            out[k] = _resolve(v, spec)
    walk(schema)
    return out


def _example_value(name, schema, spec):
    schema = _resolve(schema, spec)
    if schema.get("enum"):
        return schema["enum"][0]
    t, n = schema.get("type"), name.lower()
    if t == "boolean":
        return True
    if t == "integer":
        return 443 if "port" in n else (24 if "mask" in n else (128 if "icmp" in n else 1))
    if t == "array":
        item = _resolve(schema.get("items", {}), spec)
        return [_example_value(name, item, spec)] if item else ["example"]
    if t == "object":
        props = _properties(schema, spec)
        return {k: _example_value(k, v, spec) for k, v in list(props.items())[:6]}
    # string heuristics
    if "ipv6" in n:
        return "2001:db8::10"
    if "mask" in n and "length" not in n:
        return "255.255.255.0"
    if any(x in n for x in ("ip-address", "ipv4", "address", "gateway", "subnet", "server")):
        return "192.0.2.10"
    if n == "name":
        return "MyObject"
    if "color" in n:
        return "black"
    if "comment" in n:
        return "managed as code"
    return "example"


def _tf_name(api_type, obj):
    if obj in TF_MISSING_OBJECTS:
        return None
    prefix = "checkpoint_management_" if api_type == "management" else "checkpoint_gaia_"
    return prefix + obj.replace("-", "_")


def _ansible_name(api_type, obj):
    if obj in ANSIBLE_MISSING_OBJECTS:
        return None
    return ("cp_mgmt_" if api_type == "management" else "cp_gaia_") + obj.replace("-", "_")


def _field_support(api_type, obj, fname, tf_obj, ans_obj):
    """Per-field API/TF/Ansible support (derived)."""
    request_only = fname in REQUEST_ONLY
    tf = tf_obj is not None and (request_only or fname not in TF_OMIT_FIELDS)
    ans = ans_obj is not None  # Ansible mirrors the API field set (adds groups/details-level)
    return {"api": True, "tf": tf, "ansible": ans, "request_only": request_only}


def build_object(spec, api_type, path):
    cmd = path.lstrip("/")
    obj = re.sub(r"^(add|set)-", "", cmd)
    tf_obj, ans_obj = _tf_name(api_type, obj), _ansible_name(api_type, obj)
    props = _properties(_request_schema(spec, path), spec)
    fields, example = [], {}
    for fname, fschema in props.items():
        sup = _field_support(api_type, obj, fname, tf_obj, ans_obj)
        fields.append({"name": fname, "type": fschema.get("type", "string"),
                       "enum": fschema.get("enum"), "required": fname in (
                           (_resolve(_request_schema(spec, path), spec).get("required")) or []),
                       **sup})
        if not sup["request_only"]:
            example[fname] = _example_value(fname, fschema, spec)
    return {"name": obj, "command": cmd, "terraform": tf_obj, "ansible": ans_obj,
            "fields": fields, "example": example}


def build_version(api_type, version, spec_path):
    with open(spec_path) as f:
        spec = json.load(f)
    prefixes = ("/add-",) if api_type == "management" else ("/add-", "/set-")
    paths = sorted(p for p in spec.get("paths", {}) if p.startswith(prefixes))
    objects = [build_object(spec, api_type, p) for p in paths]
    return {"api_type": api_type, "version": version, "tool_versions": TOOL_VERSIONS,
            "source": "CP-Docs-To-Swagger OpenAPI", "object_count": len(objects), "objects": objects}


def _latest(api_type):
    root = os.path.join(SPEC_ROOT, api_type)
    vers = [d for d in os.listdir(root) if os.path.isdir(os.path.join(root, d))]
    return sorted(vers, key=lambda v: [int(x) for x in re.findall(r"\d+", v)] or [0])[-1]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", choices=["management", "gaia", "both"], default="both")
    ap.add_argument("--version", default="")
    ap.add_argument("--spec", default="")
    ap.add_argument("--out", default=OUT_DIR)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    targets = ["management", "gaia"] if args.api == "both" else [args.api]
    index = []
    for api_type in targets:
        version = args.version or _latest(api_type)
        spec_path = args.spec or os.path.join(SPEC_ROOT, api_type, version, "openapi.json")
        art = build_version(api_type, version, spec_path)
        fn = f"{api_type}-{version}.json"
        with open(os.path.join(args.out, fn), "w") as f:
            json.dump(art, f, separators=(",", ":"))
        index.append({"api_type": api_type, "version": version, "file": fn,
                      "object_count": art["object_count"]})
        print(f"{api_type} {version}: {art['object_count']} objects -> {fn}")

    # merge into the index (keep other versions already present)
    idx_path = os.path.join(args.out, "index.json")
    existing = []
    if os.path.exists(idx_path):
        with open(idx_path) as f:
            existing = json.load(f).get("artifacts", [])
    by_key = {(a["api_type"], a["version"]): a for a in existing}
    for a in index:
        by_key[(a["api_type"], a["version"])] = a
    with open(idx_path, "w") as f:
        json.dump({"artifacts": sorted(by_key.values(), key=lambda a: (a["api_type"], a["version"]))}, f, indent=2)


if __name__ == "__main__":
    main()
