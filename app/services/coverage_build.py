"""Core of the coverage-artifact generator — shared by the CLI (``tools/build_coverage.py``) and the
in-app "check for updates" endpoint.

``build_from_spec(api_type, version, spec)`` turns one OpenAPI document into the compact artifact the
/coverage page reads. The "check for updates" endpoint builds a fresh spec from Check Point's published
API docs via the in-portal converter (``fetch_spec`` → ``app.services.cp_docs``, vendored from
CP-Docs-To-Swagger) and runs this on it — no external service and no local spec files needed. TF/Ansible
support is derived from the API schema + documented divergences (the web_api side is authoritative).
"""
from __future__ import annotations

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
                   "ip-address-last": "ipv4_address_last", "subnet": "subnet4", "mask-length": "mask_length4",
                   "vpn": "vpn_communities"}
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


def _tf_field_name(api_type, fname, tf_obj):
    """The Terraform argument name for an API field, or None if TF has no equivalent. For management,
    generic fields TF splits (ip-address → ipv4_address) resolve to the real TF arg; Gaia fields are 1:1."""
    if tf_obj is None:
        return None
    if api_type == "management":
        return None if fname in _MGMT_TF_NO_FIELD else _MGMT_TF_RENAME.get(fname, fname.replace("-", "_"))
    return fname.replace("-", "_")


def _ans_field_name(fname, ans_obj):
    return None if ans_obj is None else fname.replace("-", "_")   # collections mirror the API field set


def _field_support(api_type, fname, tf_obj, ans_obj):
    tfn, ann = _tf_field_name(api_type, fname, tf_obj), _ans_field_name(fname, ans_obj)
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
        sup = _field_support(api_type, fname, tf_obj, ans_obj)
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


def fetch_spec(api_type: str, version: str = "") -> dict:
    """Build the OpenAPI spec for ``api_type``/``version`` straight from Check Point's published API
    documentation, using the in-portal converter (``app.services.cp_docs``, vendored from
    CP-Docs-To-Swagger). ``version=''`` discovers and uses the latest published version. No external
    service dependency — the portal converts the docs itself over TLS-verified httpx."""
    from app.services.cp_docs.generator import convert_checkpoint_to_openapi
    return convert_checkpoint_to_openapi(api_type=api_type, api_version=version or None)


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
    if not art["object_count"]:
        return {"ok": False, "error": f"The fetched {api_type} {ver} spec has no add-*/set-* objects."}
    write_artifact(art)
    return {"ok": True, "added": True, "api_type": api_type, "version": ver,
            "object_count": art["object_count"]}
