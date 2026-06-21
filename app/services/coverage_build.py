"""Core of the coverage-artifact generator — shared by the CLI (``tools/build_coverage.py``) and the
in-app "check for updates" endpoint.

``build_from_spec(api_type, version, spec)`` turns one OpenAPI document into the compact artifact the
/coverage page reads. The "check for updates" endpoint builds a fresh spec from Check Point's published
API docs via the in-portal converter (``fetch_spec`` → ``app.services.cp_docs``, vendored from
CP-Docs-To-Swagger) and runs this on it — no external service and no local spec files needed. TF/Ansible
support is derived from the API schema + documented divergences (the web_api side is authoritative).
"""
from __future__ import annotations

import functools
import json
import os
import re

OUT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "coverage_data")

TOOL_VERSIONS = {
    "terraform": "CheckPointSW/checkpoint v3.2.0",
    "ansible_mgmt": "check_point.mgmt",
    "ansible_gaia": "check_point.gaia",
}
REQUEST_ONLY = {"ignore-warnings", "ignore-errors", "set-if-exists", "details-level"}

# --- Management API divergences ---------------------------------------------------------------
# Management API fields Terraform exposes under a DIFFERENT name (generic field split into v4/v6).
# These are SUPPORTED in TF — just renamed — so they must NOT be flagged as gaps. Every other field
# defaults to the API name with hyphens→underscores (e.g. ipv4-address → ipv4_address).
_MGMT_TF_RENAME = {"ip-address": "ipv4_address", "ip-address-first": "ipv4_address_first",
                   "ip-address-last": "ipv4_address_last", "subnet": "subnet4", "mask-length": "mask_length4"}
# `vpn` is renamed to vpn_communities ONLY when it's the access-rule community LIST (array); on
# simple-gateway / simple-cluster `vpn` is a boolean blade that keeps its name. See _tf_field_name.
_MGMT_TF_NO_FIELD = {"groups", "details-level", "subnet-mask", "service-resource"}   # no TF arg at all
_MGMT_ANSIBLE_MISSING = {"service-gtp", "opsec-application", "server-certificate",
                         "vmware-data-center-server", "aws-data-center-server", "azure-data-center-server"}

# --- Gaia API divergences ---------------------------------------------------------------------
# Gaia API objects that actually have a check_point.gaia (cp_gaia_*) CONFIG module. Everything else
# (BGP/OSPF/RIP/PIM/ISIS routing, static-mroute, aggregate-route, arp, lldp, dhcp6, PBR, GRE/VXLAN/PPPoE,
# NFS, FIPS, …) has NO Ansible module — Ansible is read-only there → those show an Ansible gap.
_GAIA_ANSIBLE_OBJECTS = {
    "hostname", "hostname-on-login-page", "initial-setup", "physical-interface", "vlan-interface",
    "bond-interface", "bridge-interface", "loopback-interface", "alias-interface", "ipv6", "static-route",
    "dns", "ntp", "dhcp-server", "proxy", "time-and-date", "snmp", "snmp-user", "snmp-trap-receiver",
    "snmp-custom-trap", "snmp-pre-defined-traps", "syslog", "remote-syslog", "user", "role", "system-group",
    "radius", "tacacs", "allowed-clients", "password-policy", "ssh-server-settings", "expert-password",
    "grub-password", "banner", "message-of-the-day", "scheduled-job", "scheduled-job-mail",
    "scheduled-snapshot", "virtual-switch", "virtual-gateway", "dynamic-content",
    "maestro-gateway", "maestro-port", "maestro-security-group", "maestro-site", "maestro-changes",
}
# Gaia API object → cp_gaia_* module name where it isn't just hyphens→underscores.
_GAIA_ANSIBLE_MODULE = {"radius": "radius_server", "tacacs": "tacacs_server",
                        "maestro-gateway": "maestro_gateways", "maestro-port": "maestro_ports",
                        "maestro-security-group": "maestro_security_groups", "maestro-site": "maestro_sites"}
TF_MISSING_OBJECTS: set[str] = set()


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


# The CP-Docs-To-Swagger converter flattens documented nested objects to a bare ``type: string``, so a
# naive example would print the literal "example" for nat-settings / interfaces / etc. These are the
# well-known nested blocks (keyed by field name, stable across objects/versions) with a faithful example,
# sourced from the documented add-* structures. Anything flattened-but-not-here is OMITTED from the
# example (it still appears in the field table) rather than shown as a misleading scalar.
_NESTED_EXAMPLES = {
    "nat-settings": {"auto-rule": True, "method": "hide", "hide-behind": "gateway", "install-on": "All"},
    "aggressive-aging": {"enable": True, "timeout": 3600, "use-default-timeout": False},
    "interfaces": [{"name": "eth0", "subnet4": "192.0.2.0", "mask-length4": 24}],
    "host-servers": {"web-server": True,
                     "web-server-config": {"additional-ports": ["8080"], "listen-standard-port": True}},
    "start": {"date": "01-Jan-2024", "time": "08:00"},
    "end": {"date": "31-Dec-2024", "time": "17:00"},
    "recurrence": {"pattern": "Daily", "weekdays": ["Sun", "Mon"]},
    "hours-ranges": [{"enabled": True, "from": "08:00", "to": "17:00", "index": 1}],
    "track": {"type": "Log", "accounting": False, "per-connection": True},
}
_OMIT = object()   # sentinel: _build_object leaves this field out of the example snippet
# Documented nested objects the converter flattened to a bare string whose description gives no "settings"/
# "configuration" hint — omit from the example rather than print a misleading scalar. (Field table keeps them.)
_FLATTENED_NESTED = {"https-inspection", "encrypted-traffic", "dhcp", "dhcp6", "user-check", "match-ufp",
                     "match-wildcards", "cvp", "soap", "accounting", "client-customization",
                     "data-leak-prevention", "harmony-mobile", "password-history", "password-strength"}


def _example_value(name, schema, spec):
    schema = _resolve(schema, spec)
    n = name.lower()
    if name in _NESTED_EXAMPLES:               # a real nested block the OpenAPI flattened to a string
        return _NESTED_EXAMPLES[name]
    if schema.get("enum"):
        return schema["enum"][0]
    t = schema.get("type")
    desc = (schema.get("description") or "").lower()
    # A flattened nested object we don't model → OMIT (don't print a misleading scalar like "example").
    if t in (None, "string", "object") and (
            name in _FLATTENED_NESTED or "settings" in desc or "configuration" in desc
            or "settings" in n.split("-") or n.endswith(("-config", "-settings", "-configuration"))):
        return _OMIT
    if n == "tags":
        return ["lab"]
    if "mask" in n and "length" in n:          # mask-length / ipv4-mask-length → an integer, not an IP
        return 64 if "ipv6" in n else 24
    if t == "boolean":
        return True
    if t == "integer":
        if "port" in n:
            return 443
        if "mask" in n:
            return 64 if "ipv6" in n else 24
        return 1500 if "mtu" in n else (128 if "icmp" in n else 1)
    if t == "array":
        item = _resolve(schema.get("items", {}), spec)
        iv = _example_value(name, item, spec) if item else _OMIT
        return _OMIT if iv is _OMIT else [iv]
    if t == "object":
        props = _properties(schema, spec)
        out = {k: _example_value(k, v, spec) for k, v in list(props.items())[:6]}
        return {k: v for k, v in out.items() if v is not _OMIT}
    if n == "action":                          # untyped strings the converter leaves typeless
        return "Accept"
    if n == "position":
        return "top"
    if n == "version":
        return "R81.20"
    if n in ("os-name", "os"):
        return "Gaia"
    if n == "hardware":
        return "Open server"
    if n == "speed":
        return "1000M"
    if n == "duplex":
        return "full"
    if "mac" in n:
        return "00:1c:7f:11:22:33"
    if "ipv6" in n:
        return "2001:db8::10"
    if "mask" in n:                            # subnet-mask / netmask (mask-length handled above)
        return "255.255.255.0"
    if any(x in n for x in ("ip-address", "ipv4", "address", "gateway", "subnet")):
        return "192.0.2.10"
    if n == "name":
        return "MyObject"
    if "color" in n:
        return "black"
    if "comment" in n:
        return "managed as code"
    return _OMIT   # no meaningful value to synthesise → leave it out of the example (never print "example")


def _tf_obj_name(api_type, obj):
    if api_type == "management":
        return None if obj in TF_MISSING_OBJECTS else "checkpoint_management_" + obj.replace("-", "_")
    return "checkpoint_gaia_" + obj.replace("-", "_")   # the provider covers ~all Gaia objects


def _ans_obj_name(api_type, obj):
    if api_type == "management":
        return None if obj in _MGMT_ANSIBLE_MISSING else "cp_mgmt_" + obj.replace("-", "_")
    if obj not in _GAIA_ANSIBLE_OBJECTS:
        return None   # many Gaia objects (routing, arp, lldp, dhcp6, …) have no cp_gaia_* module
    return "cp_gaia_" + _GAIA_ANSIBLE_MODULE.get(obj, obj.replace("-", "_"))


def _tf_field_name(api_type, fname, tf_obj, ftype=None):
    """The Terraform argument name for an API field, or None if TF has no equivalent. For management,
    generic fields TF splits (ip-address → ipv4_address) resolve to the real TF arg; Gaia fields are 1:1."""
    if tf_obj is None:
        return None
    if api_type == "management":
        if fname in _MGMT_TF_NO_FIELD:
            return None
        if fname == "vpn":                     # community LIST → vpn_communities; boolean blade → vpn
            return "vpn_communities" if ftype == "array" else "vpn"
        return _MGMT_TF_RENAME.get(fname, fname.replace("-", "_"))
    return fname.replace("-", "_")


def _ans_field_name(fname, ans_obj):
    return None if ans_obj is None else fname.replace("-", "_")   # collections mirror the API field set


def _field_support(api_type, fname, tf_obj, ans_obj, ftype=None):
    tfn, ann = _tf_field_name(api_type, fname, tf_obj, ftype), _ans_field_name(fname, ans_obj)
    return {"api": True, "request_only": fname in REQUEST_ONLY,
            "tf": tfn is not None, "ansible": ann is not None,
            "tf_name": tfn, "ansible_name": ann}


def _build_object(spec, api_type, path):
    cmd = path.lstrip("/")
    obj = re.sub(r"^(add|set)-", "", cmd)
    tf_obj, ans_obj = _tf_obj_name(api_type, obj), _ans_obj_name(api_type, obj)
    schema = _request_schema(spec, path)
    required = (_resolve(schema, spec).get("required")) or []
    fields, example = [], {}
    for fname, fschema in _properties(schema, spec).items():
        sup = _field_support(api_type, fname, tf_obj, ans_obj, fschema.get("type"))
        fields.append({"name": fname, "type": fschema.get("type", "string"), "enum": fschema.get("enum"),
                       "required": fname in required, **sup})
        if not sup["request_only"]:
            v = _example_value(fname, fschema, spec)
            if v is not _OMIT:                 # leave flattened-nested fields we can't model out of the example
                example[fname] = v
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


def fetch_spec(api_type: str, version: str = "") -> dict:
    """Build the OpenAPI spec for ``api_type``/``version`` straight from Check Point's published API
    documentation, using the in-portal converter (``app.services.cp_docs``, vendored from
    CP-Docs-To-Swagger). ``version=''`` discovers and uses the latest published version. No external
    service dependency — the portal converts the docs itself over TLS-verified httpx."""
    from app.services.cp_docs.generator import convert_checkpoint_to_openapi
    return convert_checkpoint_to_openapi(api_type=api_type, api_version=version or None)


# --- full-spec serving (for the embedded Swagger-UI explorer) ---------------------------------
# Building a spec re-fetches the CP docs and processes ~1000 paths, so memoise the heavy part per
# (api_type, version). The target server URL only affects the small top-level ``servers`` block, which
# we patch onto a shallow copy per request — the shared paths/components are never mutated.

def _spec_sample(schema: dict, spec: dict, name: str = "", depth: int = 0):
    """A realistic example for a spec schema (request OR response), filling EVERY field. Used to
    pre-fill the explorer's "Example Value" where the CP docs gave no example — otherwise Swagger UI
    shows the schema with bare ``"string"`` placeholders, which reads as "we're showing the schema".
    (Distinct from _example_value, which OMITS unmodelled fields for the compact /coverage snippets.)"""
    schema = _resolve(schema, spec)
    if "example" in schema:
        return schema["example"]
    if schema.get("enum"):
        return schema["enum"][0]
    t, n = schema.get("type"), name.lower()
    if depth > 6:
        return "..."
    if t == "object" or schema.get("properties") or schema.get("allOf"):
        return {k: _spec_sample(v, spec, k, depth + 1) for k, v in _properties(schema, spec).items()}
    if t == "array":
        item = _resolve(schema.get("items", {}), spec)
        return [_spec_sample(item, spec, name, depth + 1)] if item else []
    if t == "boolean":
        return True
    if t in ("integer", "number"):
        return (443 if "port" in n else 12345 if "pid" in n else
                (64 if "ipv6" in n else 24) if "mask" in n else 1500 if "mtu" in n else 1)
    if "uid" in n or n == "task-id" or n.endswith("-uid"):
        return "53de74b7-91a2-4e1c-8f0b-1a2b3c4d5e6f"
    if "pid" in n:
        return "12345"
    if "state" in n or "status" in n:
        return "started"
    if "version" in n:
        return "R81.20"
    if "ipv6" in n:
        return "2001:db8::10"
    if "mask" in n and "length" not in n:
        return "255.255.255.0"
    if any(x in n for x in ("ip-address", "ipv4", "address", "gateway", "subnet")):
        return "192.0.2.10"
    if "color" in n:
        return "black"
    if any(x in n for x in ("comment", "more-info", "message", "description", "info")):
        return ""
    if "domain" in n:
        return "SMC User"
    if n == "name" or n.endswith("-name"):
        return "object-name"
    return "value"


def _inject_examples(spec: dict) -> None:
    """In place: give each operation's request/response a synthesized example where the docs gave none,
    so the explorer never shows a schema full of "string" placeholders as if it were an example."""
    for item in (spec.get("paths") or {}).values():
        op = item.get("post") or {}
        for holder in (op.get("requestBody"), ((op.get("responses") or {}).get("200") or {})):
            media = ((holder or {}).get("content") or {}).get("application/json")
            if not media or media.get("examples"):
                continue                                  # real doc examples already present → leave them
            sch = media.get("schema")
            if isinstance(sch, dict) and "example" not in sch:
                sample = _spec_sample(sch, spec)
                if sample not in (None, {}, [], "value"):
                    sch["example"] = sample


@functools.lru_cache(maxsize=6)
def _cached_spec(api_type: str, version: str) -> dict:
    spec = fetch_spec(api_type, version)
    _inject_examples(spec)        # fill request/response examples the CP docs omit (explorer only)
    return spec


def openapi_spec(api_type: str, version: str = "", server_url: str = "") -> dict:
    """The full OpenAPI document for the explorer, with the requested target server pre-filled."""
    spec = _cached_spec(api_type, version)
    if server_url:
        spec = {**spec, "servers": [{"url": server_url, "description": "Target server (from the portal)"}]}
    return spec


def explorer_spec_cache_clear() -> None:
    _cached_spec.cache_clear()


def _norm_version(spec: dict, fallback: str) -> str:
    v = str((spec.get("info") or {}).get("version") or "").strip()
    if not v:
        return fallback
    return v if v.lower().startswith("v") else "v" + v


def check_for_update(api_type: str, version: str = "") -> dict:
    """Build the (latest, or named) spec from the Check Point docs and bundle it if not already present.
    Returns {ok, api_type, version, object_count, added} or {ok:False, error}."""
    try:
        spec = fetch_spec(api_type, version)
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"Could not build the {api_type} spec from the Check Point docs — {exc}"}
    ver = version or _norm_version(spec, "vlatest")
    existing = os.path.join(OUT_DIR, f"{api_type}-{ver}.json")
    if os.path.exists(existing):
        with open(existing) as f:
            return {"ok": True, "added": False, "api_type": api_type, "version": ver,
                    "object_count": json.load(f).get("object_count", 0)}
    art = build_from_spec(api_type, ver, spec)
    if not art["object_count"]:
        return {"ok": False, "error": f"The fetched {api_type} {ver} spec has no add-*/set-* objects."}
    write_artifact(art)
    return {"ok": True, "added": True, "api_type": api_type, "version": ver,
            "object_count": art["object_count"]}
