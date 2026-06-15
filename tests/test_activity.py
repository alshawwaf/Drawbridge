"""Activity-log redaction must never leak credentials or session tokens."""
from app.services.activity import redact_body, redact_headers


def test_redact_headers_masks_secrets():
    out = redact_headers({"Authorization": "Basic abc", "X-chkp-sid": "sid123",
                          "Cookie": "session=x", "Content-Type": "application/json"})
    assert out["Authorization"] == "(masked)"
    assert out["X-chkp-sid"] == "(masked)"
    assert out["Cookie"] == "(masked)"
    assert out["Content-Type"] == "application/json"


def test_redact_body_redacts_sensitive_keys_recursively():
    out = redact_body({"user": "admin", "password": "secret",
                       "nested": {"token": "t", "ip-address": "1.1.1.1"}})
    assert out["password"] == "***"
    assert out["nested"]["token"] == "***"
    assert out["user"] == "admin"
    assert out["nested"]["ip-address"] == "1.1.1.1"


def test_redact_body_handles_lists():
    out = redact_body([{"password": "p"}, {"name": "ok"}])
    assert out[0]["password"] == "***"
    assert out[1]["name"] == "ok"
