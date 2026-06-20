"""Core of the coverage-artifact generator — shared by the CLI (``tools/build_coverage.py``) and the
in-app "check for updates" endpoint.

``build_from_spec(api_type, version, spec)`` turns one OpenAPI document into the compact artifact the
/coverage page reads. The endpoint fetches a newer spec from the user's CP-Docs-To-Swagger service
(``fetch_spec``) and runs this on it — the deployed portal has no local spec files. TF/Ansible support is
derived from the API schema + documented divergences (the web_api side is authoritative).
"""
from __future__ import annotations

import json
import os
import re

import httpx

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "coverage_data")
# The user's CP-Docs-To-Swagger service (override with COVERAGE_SPEC_URL). Used only for check-for-updates.
SPEC_BASE_URL = os.environ.get("COVERAGE_SPEC_URL", "https://swagger.ai.alshawwaf.ca")

TOOL_VERSIONS = {
    "terraform": "CheckPointSW/checkpoint v3.2.0",
    "ansible_mgmt": "check_point.mgmt",
    "ansible_gaia": "check_point.gaia",
}
REQUEST_ONLY = {"ignore-warnings", "ignore-errors", "set-if-exists", "details-level"}
TF_OMIT_FIELDS = {"groups", "ip-address", "subnet", "mask-length", "subnet-mask", "service-resource"}
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
    return ("checkpoint_management_" if api_type == "management" else "checkpoint_gaia_") + obj.replace("-", "_")


def _ansible_name(api_type, obj):
    if obj in ANSIBLE_MISSING_OBJECTS:
        return None
    return ("cp_mgmt_" if api_type == "management" else "cp_gaia_") + obj.replace("-", "_")


def _field_support(obj, fname, tf_obj, ans_obj):
    request_only = fname in REQUEST_ONLY
    return {"api": True, "request_only": request_only,
            "tf": tf_obj is not None and (request_only or fname not in TF_OMIT_FIELDS),
            "ansible": ans_obj is not None}


def _build_object(spec, api_type, path):
    cmd = path.lstrip("/")
    obj = re.sub(r"^(add|set)-", "", cmd)
    tf_obj, ans_obj = _tf_name(api_type, obj), _ansible_name(api_type, obj)
    schema = _request_schema(spec, path)
    required = (_resolve(schema, spec).get("required")) or []
    fields, example = [], {}
    for fname, fschema in _properties(schema, spec).items():
        sup = _field_support(obj, fname, tf_obj, ans_obj)
        fields.append({"name": fname, "type": fschema.get("type", "string"), "enum": fschema.get("enum"),
                       "required": fname in required, **sup})
        if not sup["request_only"]:
            example[fname] = _example_value(fname, fschema, spec)
    return {"name": obj, "command": cmd, "terraform": tf_obj, "ansible": ans_obj,
            "fields": fields, "example": example}


def build_from_spec(api_type: str, version: str, spec: dict) -> dict:
    """Turn one OpenAPI document into the coverage artifact."""
    prefixes = ("/add-",) if api_type == "management" else ("/add-", "/set-")
    paths = sorted(p for p in spec.get("paths", {}) if p.startswith(prefixes))
    objects = [_build_object(spec, api_type, p) for p in paths]
    return {"api_type": api_type, "version": version, "tool_versions": TOOL_VERSIONS,
            "source": "CP-Docs-To-Swagger OpenAPI", "object_count": len(objects), "objects": objects}


def write_artifact(art: dict, out_dir: str | None = None) -> str:
    out_dir = out_dir or OUT_DIR
    os.makedirs(out_dir, exist_ok=True)
    fn = f"{art['api_type']}-{art['version']}.json"
    with open(os.path.join(out_dir, fn), "w") as f:
        json.dump(art, f, separators=(",", ":"))
    idx_path = os.path.join(out_dir, "index.json")
    existing = []
    if os.path.exists(idx_path):
        with open(idx_path) as f:
            existing = json.load(f).get("artifacts", [])
    by_key = {(a["api_type"], a["version"]): a for a in existing}
    by_key[(art["api_type"], art["version"])] = {"api_type": art["api_type"], "version": art["version"],
                                                  "file": fn, "object_count": art["object_count"]}
    with open(idx_path, "w") as f:
        json.dump({"artifacts": sorted(by_key.values(), key=lambda a: (a["api_type"], a["version"]))}, f, indent=2)
    return fn


def fetch_spec(api_type: str, version: str = "", timeout: float = 60.0) -> dict:
    """Fetch an OpenAPI spec from the CP-Docs-To-Swagger service (TLS verified). version='' = latest."""
    url = f"{SPEC_BASE_URL}/openapi.json?api_type={api_type}" + (f"&version={version}" if version else "")
    r = httpx.get(url, timeout=timeout, follow_redirects=True)
    r.raise_for_status()
    return r.json()


def _norm_version(spec: dict, fallback: str) -> str:
    v = str((spec.get("info") or {}).get("version") or "").strip()
    if not v:
        return fallback
    return v if v.lower().startswith("v") else "v" + v


def check_for_update(api_type: str, version: str = "") -> dict:
    """Fetch the (latest, or named) spec from the service and bundle it if not already present.
    Returns {ok, api_type, version, object_count, added} or {ok:False, error}."""
    try:
        spec = fetch_spec(api_type, version)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"Could not fetch the spec from {SPEC_BASE_URL} — {exc}"}
    ver = version or _norm_version(spec, "vlatest")
    existing = os.path.join(OUT_DIR, f"{api_type}-{ver}.json")
    if os.path.exists(existing):
        with open(existing) as f:
            return {"ok": True, "added": False, "api_type": api_type, "version": ver,
                    "object_count": json.load(f).get("object_count", 0)}
    art = build_from_spec(api_type, ver, spec)
    write_artifact(art)
    return {"ok": True, "added": True, "api_type": api_type, "version": ver,
            "object_count": art["object_count"]}
