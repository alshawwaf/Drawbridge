"""Encrypted-at-rest storage for the optional saved gateway password.

Org policy: credentials at rest must use AES-256 (or stronger). We use AES-256-GCM
(authenticated encryption) with a key derived from the app secret via HKDF-SHA256.

The `cryptography` library is installed in the deployed image (requirements.txt). It is
*optional at runtime*: if it is missing (e.g. a minimal local env), `available()` returns
False, nothing is stored, and callers fall back to the per-apply password field. The app
always boots either way.
"""
from __future__ import annotations

import base64
import os

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Gateway, GatewaySecret

try:  # the dep is present in the deployed image; absent in some local/dev environments
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    _CRYPTO = True
except Exception:  # pragma: no cover - exercised only where the lib is missing
    _CRYPTO = False

_PREFIX = "v1."  # token version, so the scheme can evolve without ambiguity
_INFO = b"dcsim-gateway-password-v1"  # HKDF context-separation label


def _key() -> bytes | None:
    """Derive the 32-byte AES-256 key from the configured secret, or None if unavailable.

    Derived fresh each call (HKDF is cheap) so a config change is picked up without restart.
    """
    if not _CRYPTO:
        return None
    s = get_settings()
    base = (s.encryption_key or s.session_secret or "").encode()
    if not base:
        return None
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_INFO).derive(base)


def available() -> bool:
    """True when a password can actually be encrypted and stored (lib present + secret set)."""
    return _key() is not None


def encrypt(plaintext: str) -> str:
    key = _key()
    if key is None:
        raise RuntimeError("encryption unavailable")
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return _PREFIX + base64.urlsafe_b64encode(nonce + ct).decode()


def decrypt(token: str) -> str | None:
    key = _key()
    if key is None or not token or not token.startswith(_PREFIX):
        return None
    try:
        raw = base64.urlsafe_b64decode(token[len(_PREFIX):].encode())
        return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode()
    except Exception:
        return None


# --- DB helpers -------------------------------------------------------------------------

def _row(db: Session, gw: Gateway) -> GatewaySecret | None:
    return db.scalar(select(GatewaySecret).where(GatewaySecret.gateway_id == gw.id))


def has_password(db: Session, gw: Gateway) -> bool:
    """A usable (decryptable) password is on file for this gateway. Returns False if the
    encryption key/library is unavailable, since a stored secret can't be used then anyway."""
    if not available():
        return False
    row = _row(db, gw)
    return bool(row and row.ciphertext)


def get_password(db: Session, gw: Gateway) -> str | None:
    """Decrypt and return the saved password, or None if none is stored / cannot be decrypted."""
    row = _row(db, gw)
    return decrypt(row.ciphertext) if (row and row.ciphertext) else None


def store_password(db: Session, gw: Gateway, plaintext: str) -> None:
    """Encrypt and upsert the password. Caller ensures `plaintext` is non-empty and that
    `available()` is True (otherwise this raises)."""
    token = encrypt(plaintext)
    row = _row(db, gw)
    if row:
        row.ciphertext = token
    else:
        db.add(GatewaySecret(gateway_id=gw.id, ciphertext=token))


def clear_password(db: Session, gw: Gateway) -> None:
    """Remove any saved password for this gateway."""
    row = _row(db, gw)
    if row:
        db.delete(row)
