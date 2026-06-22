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
          "correlate_service", "correlate_application", "summarize_layer", "analyze_policy",
          "coverage_lookup")


def have_mcp() -> bool:
    """True if the MCP SDK is importable (so /mcp can be served)."""
    return _HAVE_MCP


def tool_catalog() -> list:
    """[{name, summary}] for the tools an agent gets — names + the first docstring line. Works without
    the SDK installed (reads services.mcp_tools directly), so the /mcp-guide page always renders."""
    from .services import mcp_tools as t
    out = []
    for name in _TOOLS:
        fn = getattr(t, name, None)
        summary = ""
        if fn and fn.__doc__:
            summary = " ".join(fn.__doc__.strip().split())   # collapse the docstring to one line
        out.append({"name": name, "summary": summary})
    return out


def import_error() -> str:
    return _IMPORT_ERR


def resolve_token() -> str:
    """The current MCP bearer token: the portal Setting (encrypted at rest) takes precedence, with the
    DCSIM_MCP_TOKEN env var as the fallback. Read PER REQUEST (via _BearerGuard) so an admin can set,
    rotate, or clear the token from Settings with no redeploy. "" means the endpoint is disabled."""
    try:
        from .services import app_settings
        from .config import get_settings
        # .strip() so a copy-paste trailing newline/space in the stored token or env var doesn't make
        # the endpoint require a whitespace-suffixed bearer that no client would send.
        return (app_settings.get_secret_or_env("mcp_token", get_settings().mcp_token) or "").strip()
    except Exception:  # noqa: BLE001 — never let a config read break the request path
        try:
            from .config import get_settings
            return (get_settings().mcp_token or "").strip()
        except Exception:  # noqa: BLE001
            return ""


def token_configured() -> bool:
    """True when a token is set (Setting or env) — i.e. /mcp is live. For the guide/status page."""
    return bool(resolve_token())


async def _send_json(send, status: int, body: bytes):
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"),
                            (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


class _BearerGuard:
    """Pure-ASGI bearer-token gate wrapping the MCP app (no coupling to the SDK's auth). The token is
    resolved PER REQUEST from ``token_provider`` (a callable) so it can be set/rotated/cleared at runtime
    with no redeploy. Non-http scopes (lifespan/websocket) pass straight through so the inner app's
    startup still runs. When no token is configured → 503 (endpoint disabled); a missing/wrong bearer on
    a configured endpoint → 401 (constant-time compared)."""
    def __init__(self, app, token_provider):
        self.app, self._token = app, token_provider

    async def __call__(self, scope, receive, send):
        stype = scope.get("type")
        if stype == "http":
            token = ""
            try:
                token = self._token() or ""
            except Exception:  # noqa: BLE001
                token = ""
            if not token:
                await _send_json(send, 503,
                                 b'{"error":"MCP disabled - set a bearer token in Settings -> MCP / agent '
                                 b'(or the DCSIM_MCP_TOKEN env var)"}')
                return
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode("latin-1")
            ok = auth.startswith("Bearer ") and hmac.compare_digest(auth[7:], token)
            if not ok:
                await _send_json(send, 401,
                                 b'{"error":"Unauthorized - send Authorization: Bearer <token>"}')
                return
            await self.app(scope, receive, send)
            return
        if stype == "lifespan":
            await self.app(scope, receive, send)   # let the inner session manager start/stop
            return
        if stype == "websocket":                   # no ws transport today; reject rather than pass unauth'd
            await send({"type": "websocket.close", "code": 1008})
            return
        # unknown scope type: do not forward to the inner app unguarded


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


def build_mcp_app(token_provider=resolve_token):
    """A token-guarded ASGI app to mount at /mcp — or None only if the MCP SDK isn't installed (then the
    caller just doesn't mount it). It is mounted REGARDLESS of whether a token is set yet: the guard
    resolves the token per request via ``token_provider`` and returns 503 while none is configured, so a
    token set later in Settings activates the endpoint with no redeploy."""
    if not _HAVE_MCP:
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
    return _BearerGuard(app, token_provider)


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
    DCSIM_MCP_HOST/PORT and serves Streamable-HTTP. `python -m app.mcp_server`. This out-of-portal path
    has no DB-backed Settings, so the token is env-only here (the portal Setting governs the mounted /mcp)."""
    import os
    if not _HAVE_MCP:
        raise SystemExit(f"the `mcp` SDK is not installed (install via Artifactory): {_IMPORT_ERR}")
    token = os.environ.get("DCSIM_MCP_TOKEN", "")
    if not token:
        raise SystemExit("set DCSIM_MCP_TOKEN to a strong secret first")
    app = build_mcp_app(lambda: token)
    if app is None:
        raise SystemExit("could not build the MCP app")
    import uvicorn
    uvicorn.run(app, host=os.environ.get("DCSIM_MCP_HOST", "127.0.0.1"),
                port=int(os.environ.get("DCSIM_MCP_PORT", "8765")))


if __name__ == "__main__":
    main()
