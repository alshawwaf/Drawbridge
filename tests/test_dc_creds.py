"""Datacenter credential encryption-at-rest (AES-256-GCM) + legacy-hash fallback."""
import pytest

from app.config import get_settings
from app.security import hash_password
from app.services import crypto, dc_creds, vsphere


@pytest.fixture()
def with_secret(monkeypatch):
    """Configure an encryption secret and rebuild the cached settings for the test."""
    monkeypatch.setenv("DCSIM_SESSION_SECRET", "unit-test-secret-please-ignore")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_crypto_roundtrip_and_context_separation(with_secret):
    if not crypto.available():
        pytest.skip("cryptography library unavailable")
    token = crypto.encrypt("hunter2", b"info-a")
    assert token.startswith("v1.") and "hunter2" not in token
    assert crypto.decrypt(token, b"info-a") == "hunter2"
    assert crypto.decrypt(token, b"info-b") is None          # different context → cannot decrypt
    assert crypto.decrypt("not-a-token", b"info-a") is None


def test_store_prefers_encryption_then_matches(with_secret):
    if not dc_creds.available():
        pytest.skip("cryptography library unavailable")
    frag = dc_creds.store("password", "S3cret!")
    assert "password_enc" in frag and "password_hash" not in frag
    cfg = {"username": "svc", **frag}
    assert dc_creds.configured(cfg) is True
    assert dc_creds.plaintext(cfg, "password") == "S3cret!"   # recoverable for copy-back
    assert dc_creds.matches(cfg, "S3cret!") is True
    assert dc_creds.matches(cfg, "wrong") is False
    assert dc_creds.store("password", "") == {}               # blank → no credential (open mock)


def test_matches_legacy_hash_and_open():
    legacy = {"username": "svc", "password_hash": hash_password("old-pw")}
    assert dc_creds.configured(legacy) is True
    assert dc_creds.matches(legacy, "old-pw") is True
    assert dc_creds.matches(legacy, "nope") is False
    assert dc_creds.plaintext(legacy, "password") is None     # a hash can't be revealed
    assert dc_creds.matches({}, "anything") is None           # nothing configured → open
    assert dc_creds.configured({}) is False


def test_secret_field_independent(with_secret):
    if not dc_creds.available():
        pytest.skip("cryptography library unavailable")
    cfg = {"token_id": "root@pam!cg", **dc_creds.store("secret", "tok-secret")}
    assert dc_creds.matches(cfg, "tok-secret", "secret") is True
    assert dc_creds.matches(cfg, "x", "secret") is False
    assert dc_creds.matches(cfg, "tok-secret") is None        # default field "password" not configured


class _DC:
    def __init__(self, content):
        self.token = "tok"
        self.content = content


def test_provider_auth_accepts_encrypted_credentials(with_secret):
    if not dc_creds.available():
        pytest.skip("cryptography library unavailable")
    dc = _DC({"vms": [], "auth": {"username": "admin", **dc_creds.store("password", "vmware1!")}})
    assert vsphere.auth_ok(dc, "admin", "vmware1!") is True
    assert vsphere.auth_ok(dc, "admin", "bad") is False
    assert vsphere.auth_ok(dc, "intruder", "vmware1!") is False
    assert vsphere.auth_ok(_DC({"vms": []}), "anyone", "anything") is True   # no auth configured → open
