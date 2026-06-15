"""Validation for Network Feed entries.

Per the docs, a Network Feed entry may be a single IP, a range (a-b), an IP+masklen
(a.b.c.d/len), an FQDN (host.example.com), or a non-FQDN wildcard (*.example.com). Which
shapes are accepted depends on the feed's data type: ip | domain | ip_domain. The feed is
served either as a flat list (one entry per line) or as JSON parsed by a JQ query on the gateway.
"""
import re

from pydantic import BaseModel, Field, field_validator, model_validator

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
        return validate_range(v)
    if data_type == "domain":
        return validate_domain(v)
    # ip_domain: accept an IP/range/CIDR, otherwise a domain.
    try:
        return validate_range(v)
    except ValueError:
        return validate_domain(v)


class NetworkFeedConfig(BaseModel):
    format: str = "flat"
    data_type: str = "ip_domain"
    entries: list[str] = Field(min_length=1)

    @field_validator("format")
    @classmethod
    def _check_format(cls, v: str) -> str:
        if v not in FORMATS:
            raise ValueError(f"format must be one of {FORMATS}")
        return v

    @field_validator("data_type")
    @classmethod
    def _check_data_type(cls, v: str) -> str:
        if v not in DATA_TYPES:
            raise ValueError(f"data_type must be one of {DATA_TYPES}")
        return v

    @model_validator(mode="after")
    def _validate_entries(self):
        self.entries = [validate_entry(e, self.data_type) for e in self.entries]
        return self
