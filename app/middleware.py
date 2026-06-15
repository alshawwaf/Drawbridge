"""Pure-ASGI middleware that logs inbound integration traffic (gateway feed polls and mock
Gaia API calls) to the ActivityLog — capturing request and response bodies without consuming
them from the route. Secrets are redacted before storage.
"""
import json
import time

from .services.activity import redact_body, redact_headers, write_activity

# Only log the integration surface — not UI navigation / status polling / health.
LOG_PREFIXES = ("/gdc/", "/netfeed/", "/ioc/", "/gaia_api")
_MAX_BODY = 6000


def _kind(path: str) -> str:
    return "gaia_mock" if path.startswith("/gaia_api") else "feed_poll"


def _parse(raw: bytes):
    if not raw:
        return None
    try:
        return redact_body(json.loads(raw))
    except Exception:
        return raw.decode("utf-8", "replace")[:_MAX_BODY]


class ActivityLogMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope.get("type") != "http" or not any(path.startswith(p) for p in LOG_PREFIXES):
            return await self.app(scope, receive, send)

        method = scope.get("method", "")
        req_body = bytearray()

        async def recv():
            msg = await receive()
            if msg.get("type") == "http.request" and len(req_body) < _MAX_BODY:
                req_body.extend(msg.get("body", b""))
            return msg

        resp = {"status": 0, "headers": [], "body": bytearray()}

        async def snd(msg):
            if msg.get("type") == "http.response.start":
                resp["status"] = msg.get("status", 0)
                resp["headers"] = msg.get("headers", [])
            elif msg.get("type") == "http.response.body" and len(resp["body"]) < _MAX_BODY:
                resp["body"].extend(msg.get("body", b""))
            await send(msg)

        t0 = time.perf_counter()
        try:
            await self.app(scope, recv, snd)
        finally:
            try:
                self._log(scope, path, method, bytes(req_body), resp,
                          round((time.perf_counter() - t0) * 1000))
            except Exception:
                pass

    def _log(self, scope, path, method, req_body, resp, ms):
        req_headers = {k.decode(): v.decode() for k, v in scope.get("headers", [])}
        src = req_headers.get("x-forwarded-for", "").split(",")[0].strip()
        if not src and scope.get("client"):
            src = scope["client"][0]
        resp_headers = {k.decode(): v.decode() for k, v in resp["headers"]}
        query = scope.get("query_string", b"").decode()
        detail = {
            "request": {"headers": redact_headers(req_headers), "query": query, "body": _parse(req_body)},
            "response": {"status": resp["status"], "content_type": resp_headers.get("content-type", ""),
                         "body": _parse(bytes(resp["body"]))},
        }
        write_activity(kind=_kind(path), direction="inbound", method=method, path=path,
                       source_ip=src, status=resp["status"], duration_ms=ms,
                       summary=f"{method} {path} → {resp['status']}", detail=detail)
