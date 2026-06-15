"""Validation + output models for the Generic Data Center JSON format (sk167210).

Mandatory fields per the spec: version, objects, and for each object name, id, ranges.
Only version "1.0" is supported. Each object id must be a unique UUID. Each range is a
single IP, a CIDR (a.b.c.d/len), or an inclusive range (start-end) — IPv4 or IPv6.
"""
import ipaddress
import uuid

from pydantic import BaseModel, Field, field_validator

GENERIC_DC_VERSION = "1.0"


def validate_range(value: str) -> str:
    """Return the normalized range string, or raise ValueError if malformed."""
    v = value.strip()
    if not v:
        raise ValueError("empty range")
    # Inclusive range "start-end" (IPv6 uses ':' internally, never '-', so split is safe).
    if "-" in v and not v.startswith("-"):
        lo, hi = v.split("-", 1)
        a = ipaddress.ip_address(lo.strip())
        b = ipaddress.ip_address(hi.strip())
        if a.version != b.version:
            raise ValueError(f"range endpoints differ in IP version: {value!r}")
        if int(b) < int(a):
            raise ValueError(f"range end precedes start: {value!r}")
        # Preserve the user's address formatting (consistent with single IP / CIDR below).
        return f"{lo.strip()}-{hi.strip()}"
    # CIDR / IP+masklen.
    if "/" in v:
        ipaddress.ip_network(v, strict=False)
        return v
    # Single address.
    ipaddress.ip_address(v)
    return v


class GDCObjectIn(BaseModel):
    """An object as entered by the SE. id is optional and auto-assigned if omitted."""

    name: str = Field(min_length=1, max_length=200)
    id: str | None = None
    description: str = ""
    ranges: list[str] = Field(min_length=1)

    @field_validator("id")
    @classmethod
    def _validate_id(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        uuid.UUID(v)  # raises if not a valid UUID
        return v

    @field_validator("ranges")
    @classmethod
    def _validate_ranges(cls, v: list[str]) -> list[str]:
        return [validate_range(r) for r in v]


class GDCObjectOut(BaseModel):
    name: str
    id: str
    description: str | None = None
    ranges: list[str]


class GenericDCFile(BaseModel):
    """The exact document served to the gateway."""

    version: str = GENERIC_DC_VERSION
    description: str | None = None
    objects: list[GDCObjectOut]
