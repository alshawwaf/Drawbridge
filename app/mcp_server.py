"""MCP server exposing Drawbridge's agent tools (services.mcp_tools) over Streamable-HTTP for n8n / LLM
agents. IMPORT-GUARDED on the `mcp` SDK: that package ships via Artifactory (not PyPI), so if it isn't
installed ``build_mcp_app()`` returns None and the app simply doesn't mount ``/mcp`` — the rest of
Drawbridge is unaffected. All tool LOGIC lives in services.mcp_tools (SDK-independent + unit-tested); this
file is only the thin SDK wrapper + a pure-ASGI bearer-token gate.

Activate: install `mcp` via Artifactory, set DCSIM_MCP_TOKEN, restart. The endpoint mounts at /mcp and an
agent authenticates with `Authorization: Bearer <DCSIM_MCP_TOKEN>`. Writes are further gated by the
`mcp_allow_publish` Setting (default OFF). See docs/mcp-n8n.md."""
from __future__ import annotations

import contextlib
import hmac

try:
    from mcp.server.fastmcp import FastMCP
    _HAVE_MCP, _IMPORT_ERR = True, ""
except Exception as exc:  # noqa: BLE001 — SDK absent (Artifactory-only) -> feature stays dormant
    FastMCP = None
    _HAVE_MCP, _IMPORT_ERR = False, str(exc)

# The inner Streamable-HTTP ASGI app, kept so the parent app can run ITS lifespan (the session manager's
# task group). A mounted sub-app's own lifespan never fires, so without this the manager is uninitialized.
_INNER = None

# The tools an agent can call (logic in services.mcp_tools; registered by name + docstring + type hints).
_TOOLS = ("list_management_servers", "list_access_layers", "decide_access", "apply_access",
          "correlate_service", "correlate_application", "coverage_lookup")


def have_mcp() -> bool:
    """True if the MCP SDK is importable (so /mcp can be served)."""
    return _HAVE_MCP


def import_error() -> str:
    return _IMPORT_ERR


class _BearerGuard:
    """Pure-ASGI bearer-token gate wrapping the MCP app (no coupling to the SDK's auth). Non-http scopes
    (lifespan/websocket) pass straight through so the inner app's startup still runs; http requests get a
    401 unless they carry ``Authorization: Bearer <token>`` (constant-time compared)."""
    def __init__(self, app, token: str):
        self.app, self.token = app, token

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode("latin-1")
            ok = bool(self.token) and auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], self.token)
            if not ok:
                body = b'{"error":"Unauthorized - send Authorization: Bearer <DCSIM_MCP_TOKEN>"}'
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json"),
                                        (b"content-length", str(len(body)).encode())]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def _new_server():
    # stateless_http=True makes each tool call independent -> no persistent session-manager lifespan, which
    # is what lets the app mount cleanly inside FastAPI. streamable_http_path="/" puts the handler at the
    # mount root so the endpoint is /mcp (not /mcp/mcp — FastMCP defaults its own path to /mcp). Degrade
    # gracefully if an SDK version doesn't accept one of these kwargs.
    for kwargs in ({"stateless_http": True, "streamable_http_path": "/"},
                   {"stateless_http": True}, {}):
        try:
            return FastMCP("Drawbridge", **kwargs)
        except TypeError:
            continue
    return FastMCP("Drawbridge")


def _asgi_app(mcp):
    # The Streamable-HTTP ASGI app; the accessor name has shifted across SDK versions.
    for attr in ("streamable_http_app", "http_app", "sse_app"):
        fn = getattr(mcp, attr, None)
        if callable(fn):
            try:
                return fn()
            except Exception:  # noqa: BLE001
                continue
    return None


def build_mcp_app(token: str):
    """A token-guarded ASGI app to mount at /mcp — or None if the SDK isn't installed or no token is set
    (the caller then just doesn't mount it)."""
    if not _HAVE_MCP or not token:
        return None
    from .services import mcp_tools as t
    mcp = _new_server()
    for name in _TOOLS:
        fn = getattr(t, name, None)
        if fn is not None:
            mcp.tool()(fn)              # name = fn.__name__, description = docstring, schema from hints
    app = _asgi_app(mcp)
    if app is None:
        return None
    global _INNER
    _INNER = app                          # parent lifespan runs its session manager (see mcp_lifespan)
    return _BearerGuard(app, token)


@contextlib.asynccontextmanager
async def mcp_lifespan(app):
    """Run the mounted MCP app's lifespan (its Streamable-HTTP session-manager task group) from the
    PARENT app's lifespan — a mounted sub-app's own lifespan doesn't fire, so without this a tool call
    fails with 'Task group is not initialized'. No-op when MCP isn't mounted."""
    inner = _INNER
    ctx = getattr(getattr(inner, "router", None), "lifespan_context", None)
    if inner is None or ctx is None:
        yield
        return
    async with ctx(inner):
        yield


def main():
    """Run the MCP server standalone (alternative to mounting in the portal): reads DCSIM_MCP_TOKEN +
    DCSIM_MCP_HOST/PORT and serves Streamable-HTTP. `python -m app.mcp_server`."""
    import os
    if not _HAVE_MCP:
        raise SystemExit(f"the `mcp` SDK is not installed (install via Artifactory): {_IMPORT_ERR}")
    token = os.environ.get("DCSIM_MCP_TOKEN", "")
    if not token:
        raise SystemExit("set DCSIM_MCP_TOKEN to a strong secret first")
    app = build_mcp_app(token)
    if app is None:
        raise SystemExit("could not build the MCP app")
    import uvicorn
    uvicorn.run(app, host=os.environ.get("DCSIM_MCP_HOST", "127.0.0.1"),
                port=int(os.environ.get("DCSIM_MCP_PORT", "8765")))


if __name__ == "__main__":
    main()
