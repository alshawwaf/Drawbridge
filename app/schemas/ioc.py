"""Validation for IoC (Custom Intelligence) feed content — Check Point's native CSV format.

The native "Check Point format" is positional CSV, no column header (optional metadata lines start
with ``#!``, comments with ``#``). Columns, in order:

    UNIQ-NAME, VALUE, TYPE, CONFIDENCE, SEVERITY, PRODUCT, COMMENT

Name + value + type are mandatory (the name must be unique); confidence/severity/product/comment are
optional. Type/confidence/severity tokens are taken verbatim from the R82.10 Threat Prevention Admin
Guide (Importing External Custom Intelligence Feeds in CLI).
"""
import ipaddress
import re

from pydantic import BaseModel, field_validator, model_validator

# Exact observable types accepted by the gateway (R82.10). Order = the UI dropdown order.
IOC_TYPES = (
    "IP", "IP Range", "Domain", "URL",
    "MD5", "SHA1", "SHA256",
    "Mail-subject", "Mail-from", "Mail-to", "Mail-cc", "Mail-reply-to",
)
IOC_LEVELS = ("low", "medium", "high", "critical")  # confidence + severity

# Feed output formats (sk132193). cp_csv/stix_1.x/custom_csv share the same observable validation;
# snort is rule text, not observables.
IOC_FORMATS = ("cp_csv", "stix_1.x", "custom_csv", "snort")
INDICATOR_FORMATS = ("cp_csv", "stix_1.x", "custom_csv")

# Custom-CSV delimiter choices (the literal "\t" string from the form maps to a real tab).
CUSTOM_DELIMITERS = {",": ",", "|": "|", ";": ";", "\\t": "\t", "\t": "\t"}

# Snort rule actions (the first token of a rule). Light validation only — Snort syntax is large.
SNORT_ACTIONS = ("alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop", "block")
SNORT_MAX_RULES = 6000  # sk132193: a Snort IoC feed is capped at 6000 rules


def validate_delimiter(value: str) -> str:
    """Map a delimiter choice to the real character, or raise ValueError."""
    d = CUSTOM_DELIMITERS.get(value or ",")
    if d is None:
        raise ValueError("delimiter must be one of , | ; or tab")
    return d


def validate_snort_rules(text: str) -> list[str]:
    """Keep non-comment, non-blank lines that start with a Snort action. Enforces the rule cap."""
    rules = []
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.split(None, 1)[0].lower() not in SNORT_ACTIONS:
            raise ValueError(
                f"Snort rule must start with an action ({', '.join(SNORT_ACTIONS)}) — got {line[:50]!r}")
        rules.append(line)
    if not rules:
        raise ValueError("Enter at least one Snort rule.")
    if len(rules) > SNORT_MAX_RULES:
        raise ValueError(f"A Snort IoC feed is limited to {SNORT_MAX_RULES} rules (sk132193).")
    return rules

_TYPE_CANON = {t.lower(): t for t in IOC_TYPES}
_LEVEL_SET = set(IOC_LEVELS)
_HASH_LEN = {"MD5": 32, "SHA1": 40, "SHA256": 64}
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def canonical_type(value: str) -> str:
    """Map a case-insensitive type to its canonical token, or raise ValueError."""
    t = _TYPE_CANON.get((value or "").strip().lower())
    if t is None:
        raise ValueError(f"type must be one of {', '.join(IOC_TYPES)} — got {value!r}")
    return t


# R81.20+: PRODUCT (Software Blade) must match the observable type, or the indicator won't load
# (sk132193). IP/IP Range → Anti-Bot only; hashes → Anti-Virus only; URL/Domain/Mail-* → either.
_TYPE_BLADES = {
    "URL": {"AV", "AB"}, "Domain": {"AV", "AB"},
    "IP": {"AB"}, "IP Range": {"AB"},
    "MD5": {"AV"}, "SHA1": {"AV"}, "SHA256": {"AV"},
    "Mail-subject": {"AV", "AB"}, "Mail-from": {"AV", "AB"}, "Mail-to": {"AV", "AB"},
    "Mail-cc": {"AV", "AB"}, "Mail-reply-to": {"AV", "AB"},
}
_BLADE_CANON = {"av": "AV", "ab": "AB", "anti-virus": "AV", "antivirus": "AV",
                "anti-bot": "AB", "antibot": "AB"}


def canonical_blade(value: str) -> str:
    """Map a PRODUCT token to AV or AB (empty stays empty), or raise ValueError."""
    v = (value or "").strip()
    if not v:
        return ""
    b = _BLADE_CANON.get(v.lower())
    if b is None:
        raise ValueError(f"product (Software Blade) must be AV or AB — got {value!r}")
    return b


def _check_value_for_type(value: str, type_: str) -> None:
    """Light, type-specific sanity checks for the structured types; loose for URL/Domain/Mail-*."""
    if type_ in _HASH_LEN:
        if not (_HEX_RE.match(value) and len(value) == _HASH_LEN[type_]):
            raise ValueError(f"{type_} must be {_HASH_LEN[type_]} hex characters — got {value!r}")
    elif type_ == "IP":
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise ValueError(f"IP must be a single IPv4/IPv6 address — got {value!r}")
    elif type_ == "IP Range":
        lo, sep, hi = value.partition("-")
        if not sep:
            raise ValueError(f"IP Range must be 'start-end' — got {value!r}")
        try:
            a, b = ipaddress.ip_address(lo.strip()), ipaddress.ip_address(hi.strip())
        except ValueError:
            raise ValueError(f"IP Range endpoints must be valid IPs — got {value!r}")
        if a.version != b.version or int(b) < int(a):
            raise ValueError(f"IP Range must be same-family with start ≤ end — got {value!r}")


class IndicatorIn(BaseModel):
    name: str
    value: str
    type: str
    confidence: str = ""
    severity: str = ""
    product: str = ""
    comment: str = ""

    @field_validator("name", "value", "comment", mode="before")
    @classmethod
    def _strip(cls, v: object) -> str:
        return str(v or "").strip()

    @field_validator("product", mode="before")
    @classmethod
    def _product(cls, v: object) -> str:
        return canonical_blade(str(v or ""))

    @field_validator("name")
    @classmethod
    def _name_required(cls, v: str) -> str:
        if not v:
            raise ValueError("indicator name is required (it is the unique key)")
        return v

    @field_validator("value")
    @classmethod
    def _value_required(cls, v: str) -> str:
        if not v:
            raise ValueError("indicator value is required")
        return v

    @field_validator("confidence", "severity", mode="before")
    @classmethod
    def _level(cls, v: object) -> str:
        s = str(v or "").strip().lower()
        if s and s not in _LEVEL_SET:
            raise ValueError(f"must be one of {', '.join(IOC_LEVELS)} (or blank) — got {v!r}")
        return s

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        return canonical_type(v)

    @model_validator(mode="after")
    def _value_matches_type(self) -> "IndicatorIn":
        _check_value_for_type(self.value, self.type)
        if self.product and self.product not in _TYPE_BLADES[self.type]:
            allowed = " / ".join(sorted(_TYPE_BLADES[self.type]))
            raise ValueError(
                f"{self.type} can only be enforced by {allowed} — product {self.product!r} won't load")
        return self
