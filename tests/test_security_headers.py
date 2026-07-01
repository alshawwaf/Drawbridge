"""Defensive HTTP response headers (anti-clickjacking / nosniff / referrer / HSTS)."""
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.middleware import SecurityHeadersMiddleware


def _app(https: bool) -> TestClient:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, https=https)

    @app.get("/x")
    def _x():
        return {"ok": True}

    return TestClient(app)


def test_security_headers_present_and_hsts_on_https():
    r = _app(https=True).get("/x")
    assert r.status_code == 200
    assert r.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["referrer-policy"] == "same-origin"
    assert "max-age=31536000" in r.headers["strict-transport-security"]


def test_no_hsts_when_not_https():
    r = _app(https=False).get("/x")
    assert "strict-transport-security" not in r.headers       # HSTS only when served over TLS
    assert r.headers["x-frame-options"] == "DENY"             # the rest still apply


def test_frame_ancestors_allowlist_drops_xfo_and_scopes_csp():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, https=True,
                       frame_ancestors="'self' https://*.ai.alshawwaf.ca")

    @app.get("/x")
    def _x():
        return {"ok": True}

    r = TestClient(app).get("/x")
    # An allowlist can't be expressed by X-Frame-Options, so DENY is omitted; CSP governs.
    assert "x-frame-options" not in r.headers
    assert r.headers["content-security-policy"] == "frame-ancestors 'self' https://*.ai.alshawwaf.ca"
    assert r.headers["x-content-type-options"] == "nosniff"   # other protections unchanged


def test_frame_ancestors_auto_derives_parent_domain_from_base_url():
    from types import SimpleNamespace
    from app.main import _frame_ancestors
    assert _frame_ancestors(SimpleNamespace(frame_ancestors="", base_url="https://dcsim.ai.alshawwaf.ca")) \
        == "'self' https://*.ai.alshawwaf.ca"
    assert _frame_ancestors(SimpleNamespace(frame_ancestors="", base_url="http://localhost:8000")) == "'self'"
    assert _frame_ancestors(SimpleNamespace(frame_ancestors="'none'", base_url="https://x.example.com")) \
        == "'none'"
