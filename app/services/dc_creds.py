"""Encryption-at-rest for datacenter-mock credentials (AES-256-GCM, org policy).

Stored inside ``Datacenter.content["auth"]`` as ``<field>_enc`` (an AES-GCM token) so the value can be
shown back to its owner for copy-paste into SmartConsole. When encryption is unavailable (no key /
library) we fall back to a one-way ``<field>_hash`` — never plaintext. Verification accepts either,
so datacenters created before this change keep validating.

``field`` is the credential's name: ``password`` (vCenter / NSX-T / ACI / Nutanix / OpenStack),
``secret`` (Proxmox API token), or ``token`` (Kubernetes bearer).
"""
from __future__ import annotations

import hmac

from ..security import hash_password, verify_password
from . import crypto

_INFO = b"dcsim-dc-credential-v1"


def available() -> bool:
    return crypto.available()


def encrypt(plaintext: str) -> str:
    return crypto.encrypt(plaintext, _INFO)


def decrypt(token: str) -> str | None:
    return crypto.decrypt(token, _INFO)


def store(field: str, plaintext: str) -> dict:
    """The auth-dict fragment for a secret: ``{field}_enc`` if encryption is available, else a
    one-way ``{field}_hash``. Empty input → empty dict (no credential configured = open mock)."""
    if not plaintext:
        return {}
    if available():
        return {f"{field}_enc": encrypt(plaintext)}
    return {f"{field}_hash": hash_password(plaintext)}


def configured(cfg: dict, field: str = "password") -> bool:
    """True if a credential (encrypted or legacy hash) is set — i.e. the mock should enforce auth."""
    cfg = cfg or {}
    return bool(cfg.get(f"{field}_enc") or cfg.get(f"{field}_hash"))


def plaintext(cfg: dict, field: str = "password") -> str | None:
    """The recoverable secret for display/copy, or None if not stored encrypted (or undecryptable)."""
    tok = (cfg or {}).get(f"{field}_enc")
    return decrypt(tok) if tok else None


def matches(cfg: dict, supplied: str, field: str = "password") -> bool | None:
    """Compare a supplied secret to the stored one — encrypted preferred, legacy hash fallback.

    Returns None when no secret is configured (open mock), else True/False.
    """
    cfg = cfg or {}
    enc = cfg.get(f"{field}_enc")
    if enc:
        expected = decrypt(enc)
        return expected is not None and hmac.compare_digest(supplied, expected)
    h = cfg.get(f"{field}_hash")
    if h is not None:
        return verify_password(supplied, h)
    return None
