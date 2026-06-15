"""Validation for Network Feed content.

Two authoring modes:
- Flat list: one entry per line. Each entry may be a single IP, a range (a-b), an IP+masklen
  (a.b.c.d/len), an FQDN (host.example.com), or a wildcard (*.example.com); which shapes are
  accepted depends on the data type (ip | domain | ip_domain).
- JSON: the SE authors arbitrary JSON and supplies the JQ query the gateway uses to extract the
  values. The docs don't fix a schema, so the portal only validates the JSON parses and serves
  it verbatim.
"""
import json
import re

from .generic_dc import validate_range

DATA_TYPES = ("ip", "domain", "ip_domain")
FORMATS = ("flat", "json")

_LABEL = r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
_FQDN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


def _is_fqdn(value: str) -> bool:
    if len(value) > 253 or not _FQDN_RE.match(value):
        return False
    # Reject all-numeric values (e.g. an IP address) — the TLD must contain a letter.
    return any(c.isalpha() for c in value.rsplit(".", 1)[-1])


def validate_domain(value: str) -> str:
    """Accept an FQDN or a leading-wildcard domain (*.example.com)."""
    v = value.strip()
    host = v[2:] if v.startswith("*.") else v
    if _is_fqdn(host):
        return v
    raise ValueError(f"invalid domain: {value!r}")


def validate_entry(value: str, data_type: str) -> str:
    v = value.strip()
    if not v:
        raise ValueError("empty entry")
    if data_type == "ip":
        try:
            return validate_range(v)
        except ValueError:
            raise ValueError(f"{v!r} is not a valid IP, range, or CIDR (data type is 'IP Address')")
    if data_type == "domain":
        try:
            return validate_domain(v)
        except ValueError:
            raise ValueError(f"{v!r} is not a valid domain (data type is 'Domain')")
    # ip_domain: accept an IP/range/CIDR, otherwise a domain.
    try:
        return validate_range(v)
    except ValueError:
        pass
    try:
        return validate_domain(v)
    except ValueError:
        raise ValueError(f"{v!r} is not a valid IP, range, CIDR, or domain")


def validate_json_body(body: str) -> None:
    """Ensure the custom JSON body parses. The structure is intentionally unconstrained."""
    try:
        json.loads(body)
    except Exception as exc:
        raise ValueError(f"JSON body is not valid JSON: {exc}")
