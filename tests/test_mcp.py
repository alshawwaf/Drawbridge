"""MCP agent tools + the SDK-independent glue (bearer guard, publish gate). No `mcp` SDK needed — the
tool logic and the ASGI guard are pure; the FastMCP wiring is verified separately once the SDK is
installed via Artifactory."""
import asyncio
import types

from app import mcp_server
from app.services import access_automation as aa
from app.services import app_settings, mcp_tools


def _fake_server(monkeypatch):
    monkeypatch.setattr(mcp_tools, "_server_secret",
                        lambda db, sid: (types.SimpleNamespace(id=sid, host="h"), "secret"))


# --- decide_access (preview, read-only) -----------------------------------------------------------
def test_decide_access_builds_request_and_previews(monkeypatch):
    _fake_server(monkeypatch)
    seen = {}
    monkeypatch.setattr(aa, "preview", lambda srv, sec, req, layer, package=None: seen.update(req=req, layer=layer) or {"ok": True, "outcome": "create"})
    out = mcp_tools.decide_access(1, "10.1.1.5", "Any", "Network", service="icmp")
    assert out["outcome"] == "create"
    assert seen["req"].service == "icmp" and seen["layer"] == "Network"


def test_decide_access_bad_input_returns_error_not_raise(monkeypatch):
    _fake_server(monkeypatch)
    monkeypatch.setattr(aa, "preview", lambda *a, **k: {"ok": True})
    out = mcp_tools.decide_access(1, "not-an-ip", "Any", "Network", port="443")
    assert out["ok"] is False and "error" in out


# --- apply_access publish gate --------------------------------------------------------------------
def test_apply_publish_blocked_when_setting_off(monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: False if k == "mcp_allow_publish" else None)
    called = {"execute": False}
    monkeypatch.setattr(aa, "execute", lambda *a, **k: called.update(execute=True))
    out = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443", publish=True)
    assert out["ok"] is False and out["published"] is False and "disabled" in out["error"]
    assert called["execute"] is False               # never reaches the SMS


def test_apply_publish_allowed_when_setting_on(monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: True if k == "mcp_allow_publish" else None)
    _fake_server(monkeypatch)
    seen = {}
    monkeypatch.setattr(aa, "execute", lambda srv, sec, req, layer, package=None, ticket_id="", publish=False: seen.update(publish=publish) or {"ok": True, "published": publish})
    out = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443", publish=True)
    assert out["published"] is True and seen["publish"] is True


def test_apply_dry_run_always_allowed(monkeypatch):
    monkeypatch.setattr(app_settings, "get", lambda k: False)   # publish disabled...
    _fake_server(monkeypatch)
    seen = {}
    monkeypatch.setattr(aa, "execute", lambda srv, sec, req, layer, package=None, ticket_id="", publish=False: seen.update(publish=publish) or {"ok": True})
    out = mcp_tools.apply_access(1, "10.1.1.5", "Any", "Network", port="443", publish=False)  # ...dry-run ok
    assert out["ok"] is True and seen["publish"] is False


# --- coverage_lookup (uses the bundled artifacts) -------------------------------------------------
def test_coverage_lookup_object_and_list():
    detail = mcp_tools.coverage_lookup("management", "host")
    assert detail.get("terraform") == "checkpoint_management_host" and detail.get("fields")
    miss = mcp_tools.coverage_lookup("management", "totally-not-an-object")
    assert "error" in miss and isinstance(miss.get("objects"), list)
    listing = mcp_tools.coverage_lookup("management")
    assert "host" in listing["objects"]


# --- the pure-ASGI bearer guard -------------------------------------------------------------------
def _drive(app, headers):
    """Run one ASGI http request through `app`, returning (status, body)."""
    scope = {"type": "http", "headers": headers}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        sent.append(msg)

    asyncio.run(app(scope, receive, send))
    status = next((m["status"] for m in sent if m["type"] == "http.response.start"), None)
    body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")
    return status, body


def test_bearer_guard_rejects_without_token():
    inner_called = {"hit": False}

    async def inner(scope, receive, send):
        inner_called["hit"] = True
    guard = mcp_server._BearerGuard(inner, "s3cret")
    status, body = _drive(guard, [(b"authorization", b"Bearer wrong")])
    assert status == 401 and b"Unauthorized" in body and inner_called["hit"] is False
    status2, _ = _drive(guard, [])                  # no header at all
    assert status2 == 401


def test_bearer_guard_allows_with_token():
    passed = {"hit": False}

    async def inner(scope, receive, send):
        passed["hit"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})
    guard = mcp_server._BearerGuard(inner, "s3cret")
    status, body = _drive(guard, [(b"authorization", b"Bearer s3cret")])
    assert status == 200 and body == b"ok" and passed["hit"] is True


# --- build_mcp_app degrades when the SDK isn't installed ------------------------------------------
def test_build_mcp_app_none_without_sdk_or_token():
    # the SDK isn't installed in CI -> build returns None (the portal just doesn't mount /mcp)
    if not mcp_server.have_mcp():
        assert mcp_server.build_mcp_app("tok") is None
    assert mcp_server.build_mcp_app("") is None      # no token -> never mount, regardless of SDK
    assert set(mcp_server._TOOLS) <= set(dir(mcp_tools))   # every advertised tool exists


def test_tool_catalog_lists_all_tools_with_summaries():
    cat = mcp_server.tool_catalog()
    names = {c["name"] for c in cat}
    assert names == set(mcp_server._TOOLS)                       # catalog == registered tools
    assert all(c["summary"] for c in cat)                        # every tool has a one-line summary
    assert "summarize_layer" in names and "analyze_policy" in names   # the CP-style analyze tools
