"""Server-rendered portal UI (Jinja2 + HTMX)."""
import json
import re
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..db import get_db
from ..links import public_url
from ..models import (
    Datacenter, DynamicLayer, Feed, FeedPoll, FeedType, Gateway, ManagementServer, User,
)
from ..security import (
    get_user_or_none, hash_password, new_feed_token, password_strength_error, verify_password,
)
from ..schemas.ioc import IOC_FORMATS, IOC_LEVELS, IOC_TYPES
from ..services import bundle, coverage, login_guard, table_prefs
from ..services.render import (
    custom_csv_command,
    normalize_generic_dc_content,
    normalize_ioc_content,
    normalize_network_feed_flat,
    normalize_network_feed_json,
    normalize_snort_content,
    render_feed,
)

router = APIRouter(include_in_schema=False)
TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# How many recent polls the feed page shows inline; the full history lives in the Activity log.
POLL_PREVIEW = 6


@router.get("/coverage", response_class=HTMLResponse)
def coverage_page(request: Request, api: str = "management", version: str = "",
                  db: Session = Depends(get_db)):
    """Spec-driven API vs Terraform vs Ansible coverage, per API version, with expandable examples."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    if api not in ("management", "gaia"):
        api = "management"
    version = version or coverage.latest(api)
    return templates.TemplateResponse(request, "coverage.html", coverage.page_context(api, version))


@router.get("/mcp-guide", response_class=HTMLResponse)
def mcp_guide_page(request: Request, db: Session = Depends(get_db)):
    """Onboarding for the MCP server: the tool catalog + copy-paste connect config for the common
    clients (Claude Desktop / Cursor / VS Code / n8n) + live status + the safety model."""
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    from .. import mcp_server
    from ..services import app_settings
    return templates.TemplateResponse(request, "mcp_guide.html", {
        "tools": mcp_server.tool_catalog(),
        "sdk_installed": mcp_server.have_mcp(),
        "token_set": mcp_server.token_configured(),     # an active mcp-scope API key exists -> /mcp live
        "allow_publish": bool(app_settings.get("mcp_allow_publish")),
    })


@router.post("/mcp-guide/key")
async def mcp_guide_generate_key(request: Request, db: Session = Depends(get_db)):
    """Generate an mcp-scope API key and RETURN its plaintext once, so the MCP page can drop it straight
    into the connect-config (no copy/paste, no separate Settings trip). The key is hashed at rest; this
    response is the only time the secret is shown. This is the single way to enable /mcp."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    from ..services import api_keys
    form = await request.form()
    name = (form.get("name") or "").strip() or "mcp-agent"
    row, secret = api_keys.generate(name, "mcp", created_by=user.username)
    return JSONResponse({"key": secret, "name": row.name, "scope": row.scope})


@router.get("/coverage/object")
def coverage_object(request: Request, api: str, version: str, name: str,
                    db: Session = Depends(get_db)):
    """JSON: one object's field-level API/TF/Ansible diff + the four example forms (lazy-loaded)."""
    if get_user_or_none(request, db) is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    return JSONResponse(coverage.object_detail(api, version, name))


@router.post("/coverage/update")
def coverage_update(request: Request, api: str = "management", version: str = "",
                    db: Session = Depends(get_db)):
    """Check the CP-Docs-To-Swagger service for a newer API version and bundle it if found."""
    if get_user_or_none(request, db) is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if api not in ("management", "gaia"):
        api = "management"
    from ..services import coverage_build
    result = coverage_build.check_for_update(api, version)
    if result.get("ok") and result.get("added"):
        coverage._index.cache_clear()      # surface the new version in the picker
        coverage._artifact.cache_clear()
    try:                                   # also report latest Terraform/Ansible versions vs the bundled
        result["tools"] = coverage_build.tool_version_status(api, result.get("version") or version)
    except Exception:  # noqa: BLE001 — best-effort; the CP-spec result still stands
        pass
    return JSONResponse(result)


# --- API explorer: embedded Swagger UI over the in-portal converter --------------------
def _explorer_servers(db: Session, user: User) -> dict:
    """Saved connections the explorer can target, as base URLs the spec's `servers` block uses.
    Management Servers drive web_api; Gateways expose gaia_api."""
    mgmt = db.execute(select(ManagementServer).where(ManagementServer.owner_id == user.id)).scalars().all()
    gws = db.execute(select(Gateway).where(Gateway.owner_id == user.id)).scalars().all()
    return {
        "management": [{"name": m.name, "url": f"https://{m.host}:{m.port}/web_api"} for m in mgmt],
        "gaia": [{"name": g.name, "url": f"https://{g.host}:{g.port}/gaia_api"} for g in gws],
    }


@router.get("/api-explorer", response_class=HTMLResponse)
def api_explorer_page(request: Request, api: str = "management", version: str = "",
                      db: Session = Depends(get_db)):
    """Interactive Swagger-UI explorer for the Management / Gaia API, built in-portal from the CP docs."""
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if api not in ("management", "gaia"):
        api = "management"
    servers = _explorer_servers(db, user)
    # Pre-select a registered server when one exists, so examples + Try it out target it by default
    # (falling back to the docs placeholder only when nothing is registered for this API).
    default_server = servers.get(api, [{}])[0].get("url", "") if servers.get(api) else ""
    return templates.TemplateResponse(request, "api_explorer.html", {
        "api_type": api, "version": version or coverage.latest(api),
        "versions": coverage.versions(), "servers": servers, "default_server": default_server,
    })


@router.get("/api-explorer/openapi.json")
def api_explorer_spec(request: Request, api: str = "management", version: str = "",
                      server_url: str = "", download: int = 0, db: Session = Depends(get_db)):
    """The full OpenAPI document Swagger UI loads — converted live from the CP docs, cached, with the
    chosen target server pre-filled. `version=''` = latest published. This is a standard OpenAPI 3.0
    document, so `download=1` serves it as a file ready to import into Postman or Bruno (which both build
    a request collection from it), with the selected target server baked into the spec's `servers`."""
    if get_user_or_none(request, db) is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    if api not in ("management", "gaia"):
        api = "management"
    from ..services import coverage_build
    try:
        spec = coverage_build.openapi_spec(api, version, server_url)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"Could not build the {api} {version or 'latest'} spec — {exc}"},
                            status_code=502)
    resp = JSONResponse(spec)
    if download:
        ver = re.sub(r"[^A-Za-z0-9._-]", "", version or coverage.latest(api) or "latest")
        resp.headers["Content-Disposition"] = f'attachment; filename="checkpoint-{api}-{ver}.openapi.json"'
    return resp


def _explorer_proxy_targets(db: Session, user: User) -> dict:
    """{'host:port': server} for the user's OWN saved Management Servers + Gateways — the ONLY targets the
    explorer proxy may reach. This allowlist is the SSRF guard: the proxy is never an open relay."""
    out: dict = {}
    for m in db.execute(select(ManagementServer).where(ManagementServer.owner_id == user.id)).scalars():
        out[f"{m.host}:{m.port}".lower()] = m
    for g in db.execute(select(Gateway).where(Gateway.owner_id == user.id)).scalars():
        out[f"{g.host}:{g.port}".lower()] = g
    return out


@router.api_route("/api-explorer/proxy", methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
                  include_in_schema=False)
async def api_explorer_proxy(request: Request, db: Session = Depends(get_db)):
    """Server-side proxy for the explorer's *Try it out*, so live calls work without the browser's
    cross-origin (CORS) block. STRICTLY allowlisted — it forwards ONLY to the caller's own saved
    Management Servers / Gateways (exact host:port), never an arbitrary URL, so it can't be abused as an
    open relay (SSRF). TLS is verified server-side (the server's pinned cert when set); the portal's own
    session cookie is never forwarded upstream."""
    import ssl
    import httpx
    from urllib.parse import urlparse

    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    target = request.headers.get("x-dcsim-target", "").strip()
    try:                                          # a hostile header (bad IPv6 / port) must 400, not 500
        parsed = urlparse(target) if target else None
        port = parsed.port if parsed else None
    except ValueError:
        parsed, port = None, None
    if not parsed or parsed.scheme not in ("http", "https") or not parsed.hostname:
        return JSONResponse({"error": "Missing or invalid X-Dcsim-Target URL."}, status_code=400)
    port = port or (443 if parsed.scheme == "https" else 80)
    key = f"{parsed.hostname}:{port}".lower()
    server = _explorer_proxy_targets(db, user).get(key)
    if server is None:
        return JSONResponse(
            {"error": f"Refused — {parsed.hostname}:{port} is not one of your saved servers. The explorer "
                      "only proxies to Management Servers / Gateways you've added (this prevents the portal "
                      "being used as an open proxy). Add it under Layers & Gateways, then retry."},
            status_code=403)

    from ..services.mgmt_api import _verify_for
    try:                                          # a malformed stored pin is a local config problem, not "upstream failed"
        verify = _verify_for(server)
    except ssl.SSLError:
        return JSONResponse({"error": f"The pinned certificate stored for {key} is invalid PEM — re-add the "
                                      "server's certificate on its Edit page.", "via": "portal-proxy"},
                            status_code=502)
    # Drop the full hop-by-hop set (RFC 7230) so httpx owns request framing from content=body — a stray
    # Transfer-Encoding alongside our Content-Length would be a request-smuggling primitive. Also never
    # forward the portal's own session cookie / forwarded-* headers upstream.
    drop = {"host", "cookie", "content-length", "connection", "accept-encoding",
            "x-dcsim-target", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
            "transfer-encoding", "te", "trailer", "trailers", "upgrade", "keep-alive",
            "proxy-authorization", "proxy-authenticate"}
    fwd = {k: v for k, v in request.headers.items() if k.lower() not in drop}
    body = await request.body()
    if len(body) > 2_000_000:                     # cap the relayed request body (parity with the response cap)
        return JSONResponse({"error": "Request body too large (max 2 MB for the explorer proxy)."},
                            status_code=413)
    try:
        async with httpx.AsyncClient(verify=verify, timeout=20.0,
                                     follow_redirects=False) as client:   # no redirect-based SSRF
            r = await client.request(request.method, target, content=body, headers=fwd)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"Upstream request to {key} failed: {exc}", "via": "portal-proxy"},
                            status_code=502)
    content = r.content[:2_000_000]   # truncate what we relay to the browser (allowlisted own-servers + 20s timeout bound the upstream size)
    return Response(content=content, status_code=r.status_code,
                    media_type=r.headers.get("content-type", "application/json"))

# --- Generic Data Center default (the canonical sk167210 sample) -----------------------
DEFAULT_FEED_NAME = "Generic-DC-Example"
DEFAULT_FEED_DESCRIPTION = "Generic Data Center file example"
DEFAULT_OBJECTS_TEXT = (
    "Object A name = 91.198.174.192, 20.0.0.0/24, 10.1.1.2-10.1.1.10 | Example for IPv4 addresses\n"
    "Object B name = 2001:0db8:85a3:0000:0000:8a2e:0370:7334, "
    "0064:ff9b:0000:0000:0000:0000:1234:5678/96, "
    "2001:0db8:85a3:0000:0000:8a2e:2020:0-2001:0db8:85a3:0000:0000:8a2e:2020:5 | Example for IPv6 addresses"
)

# --- Network Feed default (a small mixed blocklist) ------------------------------------
DEFAULT_NETFEED_NAME = "Network-Feed-Example"
DEFAULT_NETFEED_DESCRIPTION = "Demo blocklist"
# Per-data-type example entries; the form swaps to the matching set when data type changes,
# so the prefilled sample always validates under the selected type.
NETFEED_EXAMPLES = {
    "ip": "198.51.100.0/24\n203.0.113.10\n203.0.113.20-203.0.113.40",
    "domain": "*.malicious-example.com\nphishing-example.net\nbad.example.org",
    "ip_domain": (
        "198.51.100.0/24\n203.0.113.10\n203.0.113.20-203.0.113.40\n"
        "*.malicious-example.com\nphishing-example.net"
    ),
}
DEFAULT_NETFEED_ENTRIES = NETFEED_EXAMPLES["ip_domain"]
# JSON mode is free-form: the SE authors any JSON and supplies the JQ query to extract values.
DEFAULT_NETFEED_JSON_BODY = (
    "{\n"
    '  "version": "1.0",\n'
    '  "blocklist": [\n'
    '    { "value": "*.malicious-example.com" },\n'
    '    { "value": "phishing-example.net" },\n'
    '    { "value": "bad.example.org" }\n'
    "  ]\n"
    "}"
)
DEFAULT_JQ_QUERY = ".blocklist[].value"

# --- IoC (Custom Intelligence) feed default — one line per type, all safe demo values ---
DEFAULT_IOC_NAME = "IoC-Feed-Example"
DEFAULT_IOC_DESCRIPTION = "Demo threat-intel indicators"
# Quick-entry: 'value, type[, confidence, severity, product, comment]'. The MD5 is the EICAR test hash.
DEFAULT_IOC_INDICATORS_TEXT = (
    "203.0.113.66, IP, high, high, AB, C2 beacon\n"
    "198.51.100.10-198.51.100.40, IP Range, medium, high, AB, Known-bad range\n"
    "malware-c2.example.com, Domain, high, critical, AB, Botnet C2\n"
    "http://drive-by.example.net/payload, URL, medium, high, AV, Drive-by host\n"
    "44d88612fea8a8f36de82e1278abb02f, MD5, high, high, AV, EICAR test file"
)
# Snort-format default (each line starts with an action). Two simple, well-formed demo rules.
DEFAULT_SNORT_RULES = (
    'alert tcp any any -> any 80 (msg:"DCSIM demo - suspicious URI"; content:"/malware.bin"; '
    'http_uri; sid:1000001; rev:1;)\n'
    'alert ip 203.0.113.66 any -> any any (msg:"DCSIM demo - known-bad source"; sid:1000002; rev:1;)'
)


def _default_form() -> dict:
    return {
        "name": DEFAULT_FEED_NAME,
        "description": DEFAULT_FEED_DESCRIPTION,
        "interval_seconds": get_settings().default_gdc_interval,
        "auth_header_key": "",
        "objects_text": DEFAULT_OBJECTS_TEXT,
    }


def _default_network_form() -> dict:
    return {
        "name": DEFAULT_NETFEED_NAME,
        "description": DEFAULT_NETFEED_DESCRIPTION,
        "data_type": "ip_domain",
        "feed_format": "flat",
        "entries_text": DEFAULT_NETFEED_ENTRIES,
        "json_body": DEFAULT_NETFEED_JSON_BODY,
        "jq_query": DEFAULT_JQ_QUERY,
        "interval_seconds": 3600,
        "basic_user": "",
    }


def _default_ioc_form() -> dict:
    return {
        "name": DEFAULT_IOC_NAME,
        "description": DEFAULT_IOC_DESCRIPTION,
        "ioc_format": "cp_csv",
        "indicators_text": DEFAULT_IOC_INDICATORS_TEXT,
        "snort_rules": DEFAULT_SNORT_RULES,
        "delimiter": ",",
        "comment": "#",
        "interval_seconds": 3600,
        "basic_user": "",
    }


def parse_indicators_text(text: str) -> list[dict]:
    """IoC quick-entry: one per line, 'value, type[, confidence, severity, product, comment]'.

    Names are auto-assigned (ioc-N — the unique key SEs don't care about). Splitting keeps at most 6
    fields so commas inside the trailing comment survive. '#' lines and blanks are ignored.
    """
    indicators: list[dict] = []
    n = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",", 5)]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise ValueError(
                f"Line must be 'value, type[, confidence, severity, product, comment]': {raw.strip()!r}"
            )
        parts += [""] * (6 - len(parts))
        n += 1
        value, type_, conf, sev, prod, comment = parts
        indicators.append({"name": f"ioc-{n}", "value": value, "type": type_,
                           "confidence": conf, "severity": sev, "product": prod, "comment": comment})
    if not indicators:
        raise ValueError("Enter at least one indicator.")
    return indicators


def parse_objects_text(text: str) -> list[dict]:
    """Generic DC quick-entry: one object per line, 'Name = range1, range2 | optional description'."""
    objects: list[dict] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        description = ""
        if "|" in line:
            line, description = (part.strip() for part in line.split("|", 1))
        if "=" not in line:
            raise ValueError(f"Line must be 'Name = range1, range2': {raw.strip()!r}")
        name, rhs = line.split("=", 1)
        ranges = [r.strip() for r in rhs.split(",") if r.strip()]
        if not name.strip() or not ranges:
            raise ValueError(f"Line needs a name and at least one range: {raw.strip()!r}")
        objects.append({"name": name.strip(), "description": description, "ranges": ranges})
    if not objects:
        raise ValueError("Enter at least one object.")
    return objects


def parse_entries_text(text: str) -> list[str]:
    """Network Feed quick-entry: one entry per line; '#' lines and blanks are ignored."""
    entries = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    if not entries:
        raise ValueError("Enter at least one entry.")
    return entries


def _item_count(feed: Feed) -> int:
    if feed.type == FeedType.network_feed:
        return len(feed.content.get("entries", []))
    if feed.type == FeedType.ioc:
        if feed.content.get("format") == "snort":
            return len(feed.content.get("rules", []))
        return len(feed.content.get("indicators", []))
    return len(feed.content.get("objects", []))


_DT_LABELS = {"ip": "IP", "domain": "Domain", "ip_domain": "IP/Domain"}


def _count_label(feed: Feed) -> str:
    # JSON feeds have a custom structure we don't parse, so item count is N/A.
    if feed.type == FeedType.network_feed and feed.content.get("format") == "json":
        return "—"
    return str(_item_count(feed))


def _selections_label(feed: Feed) -> str:
    """Short description of a feed's format/data-type selections (shown + filterable in the table)."""
    if feed.type != FeedType.network_feed:
        return ""
    fmt = "JSON" if feed.content.get("format") == "json" else "Flat list"
    return f"{fmt} · {_DT_LABELS.get(feed.content.get('data_type', ''), '')}"


def _flash(request: Request, text: str, kind: str = "success") -> None:
    # Cap length: the flash rides in the signed session cookie (~4KB browser limit); an overlong
    # message would silently drop the whole cookie and log the user out.
    request.session["flash"] = {"text": (text or "")[:800], "type": kind}
    # Also persist it as a notification for the header bell (review/delete later). Best-effort: a
    # notification write must never break the request that flashed.
    uid = request.session.get("uid")
    if uid:
        try:
            from ..db import SessionLocal
            from ..services import notifications
            with SessionLocal() as db:
                notifications.add(db, uid, text or "", kind)
        except Exception:  # noqa: BLE001
            pass


def _clamp_interval(value, default: int = 3600) -> int:
    """Server-side guard for poll intervals (the client min=1 isn't authoritative): 1s .. 24h."""
    try:
        return max(1, min(int(value), 86400))
    except (TypeError, ValueError):
        return default


def _pop_flash(request: Request) -> dict | None:
    return request.session.pop("flash", None)


def _owned(db: Session, feed_id: int, user: User) -> Feed:
    feed = db.get(Feed, feed_id)
    if feed is None or feed.owner_id != user.id:
        raise HTTPException(status_code=404, detail="Feed not found")
    return feed


# --- Auth ------------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {"error": None})


@router.post("/login")
def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    ip = login_guard.client_ip(request)
    wait = login_guard.locked_for(db, ip)
    if wait:
        return templates.TemplateResponse(
            request, "login.html",
            {"error": f"Too many failed attempts. Try again in {wait}s."}, status_code=429)
    user = db.scalar(select(User).where(User.username == username))
    if user is None or not verify_password(password, user.password_hash):
        login_guard.record_failure(db, ip)
        return templates.TemplateResponse(
            request, "login.html", {"error": "Invalid credentials"}, status_code=401
        )
    login_guard.record_success(db, ip)
    request.session["uid"] = user.id
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/account", response_class=HTMLResponse)
def account_page(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(request, "account.html",
                                      {"user": user, "flash": _pop_flash(request)})


@router.post("/account/password")
def change_password(
    request: Request,
    current: str = Form(...),
    new: str = Form(...),
    confirm: str = Form(...),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if not verify_password(current, user.password_hash):
        _flash(request, "Current password is incorrect.", "error")
    elif new != confirm:
        _flash(request, "New passwords do not match.", "error")
    elif (err := password_strength_error(new)):
        _flash(request, err, "error")
    else:
        user.password_hash = hash_password(new)
        db.commit()
        _flash(request, "Password changed.")
    return RedirectResponse("/account", status_code=303)


@router.post("/account/profile")
def update_profile(
    request: Request,
    first_name: str = Form(""),
    last_name: str = Form(""),
    email: str = Form(""),
    title: str = Form(""),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    email = (email or "").strip()
    if email and ("@" not in email or " " in email or len(email) > 200):
        _flash(request, "That doesn't look like a valid email address.", "error")
        return RedirectResponse("/account", status_code=303)
    user.first_name = (first_name or "").strip()[:80]
    user.last_name = (last_name or "").strip()[:80]
    user.email = email
    user.title = (title or "").strip()[:120]
    db.commit()
    _flash(request, "Profile saved.")
    return RedirectResponse("/account", status_code=303)


# --- Home ------------------------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)

    def _count(model):
        return db.scalar(select(func.count()).select_from(model)
                         .where(model.owner_id == user.id)) or 0

    counts = {"feeds": _count(Feed), "datacenters": _count(Datacenter), "gateways": _count(Gateway),
              "management": _count(ManagementServer), "layers": _count(DynamicLayer)}
    return templates.TemplateResponse(request, "home.html",
                                      {"user": user, "counts": counts, "flash": _pop_flash(request)})


# --- Feeds -----------------------------------------------------------------------------
@router.get("/feeds", response_class=HTMLResponse)
def feeds_list(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feeds = db.scalars(
        select(Feed).where(Feed.owner_id == user.id).order_by(Feed.created_at.desc())
    ).all()
    rows = [{
        "feed": f, "url": public_url(f),
        "count": _count_label(f), "selections": _selections_label(f),
    } for f in feeds]
    type_counts: dict[str, int] = {}
    for f in feeds:
        type_counts[f.type.value] = type_counts.get(f.type.value, 0) + 1
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"user": user, "rows": rows, "type_counts": type_counts, "flash": _pop_flash(request),
         "cols": table_prefs.spec("feeds"),
         "vis": table_prefs.visible_columns(db, user.id, "feeds")},
    )


# --- PoV bundle: export / import the whole simulated environment -----------------------
@router.get("/portal/export")
def portal_export(request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    body = json.dumps(bundle.export_bundle(db, user), indent=2)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": 'attachment; filename="dcsim-pov-bundle.json"'})


@router.post("/portal/import")
async def portal_import(request: Request, file: UploadFile = File(None), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if file is None or not file.filename:
        _flash(request, "Choose a bundle file to import.", "error")
        return RedirectResponse("/", status_code=303)
    raw = await file.read()
    if len(raw) > 8 * 1024 * 1024:
        _flash(request, "Bundle too large (max 8 MB).", "error")
        return RedirectResponse("/", status_code=303)
    try:
        data = json.loads(raw.decode("utf-8"))
        result = bundle.import_bundle(db, user, data)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        _flash(request, f"Import failed: {exc}", "error")
        return RedirectResponse("/", status_code=303)
    c = result["counts"]
    msg = (f"Imported {c['feeds']} feed(s), {c['datacenters']} datacenter(s), "
           f"{c['gateways']} gateway(s), {c['dynamic_layers']} layer(s). "
           "Credentials aren’t included in bundles — re-enter them on each item.")
    if result["skipped"]:
        msg += " Skipped: " + "; ".join(result["skipped"]) + "."
    _flash(request, msg)
    return RedirectResponse("/", status_code=303)


@router.post("/portal/seed")
def portal_seed(request: Request, preset: str = Form("demo"), db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    if preset == "sbt_lab":
        c = bundle.import_bundle(db, user, bundle.sbt_lab_bundle())["counts"]
        _flash(request, f"Seeded the SBT Lab Environment: {c['datacenters']} datacenters (mock vCenter + "
                        f"NSX-T mirroring the lab VMs at their real IPs), {c['feeds']} feeds, "
                        f"{c['management_servers']} management server + {c['gateways']} gateway profile. "
                        "Connect CloudGuard to SBT-vCenter to import the VMs.")
        return RedirectResponse("/", status_code=303)
    result = bundle.import_bundle(db, user, bundle.seed_bundle())
    c = result["counts"]
    extra = ""
    # Best-effort: start a gentle live scenario on the seeded OpenStack DC so the demo opens "live".
    try:
        from ..models import Datacenter, DatacenterBaseline
        from ..services import scenario_runner, scenarios
        dc = db.scalars(select(Datacenter).where(Datacenter.owner_id == user.id,
                        Datacenter.name == "OpenStack-Demo").order_by(Datacenter.id.desc())).first()
        if dc:
            preset = next((p["key"] for p in scenarios.list_presets(dc.provider, dc.content) if p["count"]), None)
            if preset:
                if dc.baseline is None:
                    db.add(DatacenterBaseline(datacenter_id=dc.id, content=scenarios.snapshot(dc.content)))
                    db.commit()
                label, steps = scenarios.plan_preset(preset, dc.provider, dc.content)
                scenario_runner.start_run(dc.id, dc.name, label, steps, 8)
                extra = f" A live scenario (“{label}”) is now running on {dc.name} — watch the Activity log."
    except Exception:
        pass
    _flash(request, f"Seeded a demo environment: {c['feeds']} feeds, {c['datacenters']} datacenters, "
                    f"{c['gateways']} gateway, {c['dynamic_layers']} dynamic layer.{extra}")
    return RedirectResponse("/", status_code=303)


# --- New feed: chooser then per-type forms ---------------------------------------------
@router.get("/feeds/new")
def new_feed_redirect(request: Request, db: Session = Depends(get_db)):
    # The feed-type picker is a dropdown menu now; send direct hits to the Generic DC form.
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return RedirectResponse("/feeds/new/generic-dc", status_code=303)


@router.get("/feeds/new/generic-dc", response_class=HTMLResponse)
def new_generic_page(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request, "feed_new_generic.html", {"error": None, "form": _default_form()}
    )


@router.post("/feeds/new/generic-dc")
def create_generic(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    interval_seconds: int = Form(10),
    auth_header_key: str = Form(""),
    auth_header_value: str = Form(""),
    objects_text: str = Form(""),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        content = normalize_generic_dc_content(parse_objects_text(objects_text), description)
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "feed_new_generic.html",
            {"error": str(exc), "form": {
                "name": name, "description": description, "interval_seconds": interval_seconds,
                "auth_header_key": auth_header_key, "objects_text": objects_text,
            }},
            status_code=400,
        )
    feed = Feed(
        token=new_feed_token(),
        type=FeedType.generic_dc,
        name=name,
        description=description,
        content=content,
        interval_seconds=_clamp_interval(interval_seconds),
        auth_header_key=auth_header_key or None,
        auth_header_value=auth_header_value or None,
        owner_id=user.id,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    _flash(request, f"Generic Data Center feed “{name}” created.")
    return RedirectResponse(f"/feeds/{feed.id}", status_code=303)


@router.get("/feeds/new/network-feed", response_class=HTMLResponse)
def new_network_page(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "feed_new_network.html",
        {"error": None, "form": _default_network_form(), "examples": NETFEED_EXAMPLES},
    )


@router.post("/feeds/new/network-feed")
def create_network(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    data_type: str = Form("ip_domain"),
    feed_format: str = Form("flat"),
    entries_text: str = Form(""),
    json_body: str = Form(""),
    jq_query: str = Form(""),
    interval_seconds: int = Form(3600),
    basic_user: str = Form(""),
    basic_pass: str = Form(""),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        if feed_format == "json":
            content = normalize_network_feed_json(json_body, jq_query, data_type)
        else:
            content = normalize_network_feed_flat(parse_entries_text(entries_text), data_type)
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "feed_new_network.html",
            {"error": str(exc), "examples": NETFEED_EXAMPLES, "form": {
                "name": name, "description": description, "data_type": data_type,
                "feed_format": feed_format, "entries_text": entries_text,
                "json_body": json_body, "jq_query": jq_query,
                "interval_seconds": interval_seconds, "basic_user": basic_user,
            }},
            status_code=400,
        )
    feed = Feed(
        token=new_feed_token(),
        type=FeedType.network_feed,
        name=name,
        description=description,
        content=content,
        interval_seconds=_clamp_interval(interval_seconds),
        auth_header_key=basic_user or None,
        auth_header_value=basic_pass or None,
        owner_id=user.id,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    _flash(request, f"Network Feed “{name}” created.")
    return RedirectResponse(f"/feeds/{feed.id}", status_code=303)


@router.get("/feeds/new/ioc", response_class=HTMLResponse)
def new_ioc_page(request: Request, db: Session = Depends(get_db)):
    if get_user_or_none(request, db) is None:
        return RedirectResponse("/login", status_code=303)
    return templates.TemplateResponse(
        request,
        "feed_new_ioc.html",
        {"error": None, "form": _default_ioc_form(), "ioc_types": IOC_TYPES, "ioc_levels": IOC_LEVELS},
    )


@router.post("/feeds/new/ioc")
def create_ioc(
    request: Request,
    name: str = Form(...),
    description: str = Form(""),
    interval_seconds: int = Form(3600),
    basic_user: str = Form(""),
    basic_pass: str = Form(""),
    ioc_format: str = Form("cp_csv"),
    indicators_text: str = Form(""),
    snort_rules: str = Form(""),
    delimiter: str = Form(","),
    comment: str = Form("#"),
    db: Session = Depends(get_db),
):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    try:
        if ioc_format == "snort":
            content = normalize_snort_content(snort_rules)
        else:
            content = normalize_ioc_content(parse_indicators_text(indicators_text), description,
                                            ioc_format, delimiter, comment)
    except Exception as exc:
        return templates.TemplateResponse(
            request,
            "feed_new_ioc.html",
            {"error": str(exc), "ioc_types": IOC_TYPES, "ioc_levels": IOC_LEVELS, "form": {
                "name": name, "description": description, "interval_seconds": interval_seconds,
                "basic_user": basic_user, "ioc_format": ioc_format, "indicators_text": indicators_text,
                "snort_rules": snort_rules, "delimiter": delimiter, "comment": comment,
            }},
            status_code=400,
        )
    feed = Feed(
        token=new_feed_token(),
        type=FeedType.ioc,
        name=name,
        description=description,
        content=content,
        interval_seconds=_clamp_interval(interval_seconds),
        auth_header_key=basic_user or None,
        auth_header_value=basic_pass or None,
        owner_id=user.id,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    _flash(request, f"IoC feed “{name}” created.")
    return RedirectResponse(f"/feeds/{feed.id}", status_code=303)


# --- Edit a feed -----------------------------------------------------------------------
# The create forms (feed_new_*.html) are reused for editing: GET prefills them by serializing the
# stored content back to the quick-entry text format, POST re-parses and updates in place.

def _ser_gdc_objects(objects: list[dict]) -> str:
    """Generic DC: 'Name = range1, range2 | description' per line (reverse of parse_objects_text)."""
    out = []
    for o in objects or []:
        line = f"{o['name']} = {', '.join(o.get('ranges') or [])}"
        if o.get("description"):
            line += f" | {o['description']}"
        out.append(line)
    return "\n".join(out)


def _ser_ioc_indicators(indicators: list[dict]) -> str:
    """IoC: 'value, type[, confidence, severity, product, comment]' per line, trailing blanks trimmed."""
    out = []
    for i in indicators or []:
        fields = [i.get("value", ""), i.get("type", ""), i.get("confidence", ""),
                  i.get("severity", ""), i.get("product", ""), i.get("comment", "")]
        while len(fields) > 2 and not fields[-1]:
            fields.pop()
        out.append(", ".join(fields))
    return "\n".join(out)


_FEED_EDIT_TEMPLATE = {
    FeedType.generic_dc: "feed_new_generic.html",
    FeedType.network_feed: "feed_new_network.html",
    FeedType.ioc: "feed_new_ioc.html",
}


def _feed_build_form(feed: Feed) -> dict:
    c = feed.content or {}
    key = feed.auth_header_key or ""
    form = {"name": feed.name, "description": feed.description or "", "interval_seconds": feed.interval_seconds}
    if feed.type == FeedType.generic_dc:
        form.update(objects_text=_ser_gdc_objects(c.get("objects")), auth_header_key=key)
    elif feed.type == FeedType.network_feed:
        fmt = c.get("format", "flat")
        form.update(data_type=c.get("data_type", "ip_domain"), feed_format=fmt, basic_user=key,
                    entries_text="\n".join(c.get("entries") or []) if fmt == "flat" else "",
                    json_body=c.get("body", "") if fmt == "json" else "",
                    jq_query=c.get("jq_query", "") if fmt == "json" else "")
    elif feed.type == FeedType.ioc:
        fmt = c.get("format", "cp_csv")
        form.update(ioc_format=fmt, delimiter=c.get("delimiter", ","), comment=c.get("comment", "#"), basic_user=key,
                    indicators_text=_ser_ioc_indicators(c.get("indicators")) if fmt != "snort" else "",
                    snort_rules="\n".join(c.get("rules") or []) if fmt == "snort" else "")
    return form


def _feed_parse_edit(feed: Feed, raw) -> tuple[dict, dict]:
    """Rebuild (content, attribute-updates) from the submitted edit form (raises ValueError on bad input).
    A blank password keeps the stored one; clearing the username (or the password) reverts to an open feed."""
    name = (raw.get("name") or "").strip()
    if not name:
        raise ValueError("Feed name is required.")
    description = (raw.get("description") or "").strip()
    try:
        interval = int(raw.get("interval_seconds") or feed.interval_seconds)
    except (TypeError, ValueError):
        interval = feed.interval_seconds

    if feed.type == FeedType.generic_dc:
        content = normalize_generic_dc_content(parse_objects_text(raw.get("objects_text", "")), description)
        auth_key, pass_field = (raw.get("auth_header_key") or "").strip(), "auth_header_value"
    elif feed.type == FeedType.network_feed:
        dt = raw.get("data_type", "ip_domain")
        if raw.get("feed_format", "flat") == "json":
            content = normalize_network_feed_json(raw.get("json_body", ""), raw.get("jq_query", ""), dt)
        else:
            content = normalize_network_feed_flat(parse_entries_text(raw.get("entries_text", "")), dt)
        auth_key, pass_field = (raw.get("basic_user") or "").strip(), "basic_pass"
    elif feed.type == FeedType.ioc:
        if raw.get("ioc_format", "cp_csv") == "snort":
            content = normalize_snort_content(raw.get("snort_rules", ""))
        else:
            content = normalize_ioc_content(parse_indicators_text(raw.get("indicators_text", "")), description,
                                            raw.get("ioc_format", "cp_csv"), raw.get("delimiter", ","),
                                            raw.get("comment", "#"))
        auth_key, pass_field = (raw.get("basic_user") or "").strip(), "basic_pass"
    else:
        raise ValueError("This feed type can’t be edited.")

    new_pass = raw.get(pass_field) or ""
    val_final = new_pass or (feed.auth_header_value if auth_key else None)  # blank keeps the stored value
    if raw.get("clear_creds") or not auth_key or not val_final:
        key_final, val_final = None, None  # open feed: explicit clear, or a missing username/password
    else:
        key_final = auth_key
    return content, {"name": name, "description": description, "interval_seconds": interval,
                     "auth_header_key": key_final, "auth_header_value": val_final}


def _feed_edit_ctx(feed: Feed, form: dict, error: str | None) -> dict:
    ctx = {"error": error, "form": form, "editing": True, "creds_set": bool(feed.auth_header_key),
           "action": f"/feeds/{feed.id}/edit", "cancel": f"/feeds/{feed.id}"}
    if feed.type == FeedType.network_feed:
        ctx["examples"] = NETFEED_EXAMPLES
    elif feed.type == FeedType.ioc:
        ctx.update(ioc_types=IOC_TYPES, ioc_levels=IOC_LEVELS)
    return ctx


@router.get("/feeds/{feed_id}/edit", response_class=HTMLResponse)
def feed_edit(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feed = _owned(db, feed_id, user)
    tmpl = _FEED_EDIT_TEMPLATE.get(feed.type)
    if not tmpl:
        raise HTTPException(status_code=404, detail="This feed type can't be edited")
    return templates.TemplateResponse(request, tmpl, _feed_edit_ctx(feed, _feed_build_form(feed), None))


@router.post("/feeds/{feed_id}/edit")
async def feed_edit_save(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feed = _owned(db, feed_id, user)
    tmpl = _FEED_EDIT_TEMPLATE.get(feed.type)
    if not tmpl:
        raise HTTPException(status_code=404, detail="This feed type can't be edited")
    raw = await request.form()
    try:
        content, updates = _feed_parse_edit(feed, raw)
    except Exception as exc:
        form = {k: raw.get(k, v) for k, v in _feed_build_form(feed).items()}
        return templates.TemplateResponse(request, tmpl, _feed_edit_ctx(feed, form, str(exc)), status_code=400)
    feed.content = content
    for attr, val in updates.items():
        setattr(feed, attr, val)
    db.commit()
    _flash(request, f"Feed “{feed.name}” updated.")
    return RedirectResponse(f"/feeds/{feed.id}", status_code=303)


@router.post("/feeds/{feed_id}/quick-edit")
async def feed_quick_edit(feed_id: int, request: Request, db: Session = Depends(get_db)):
    """Inline single-field edit from the feed detail page (JSON {field, value}): rename, or set/clear
    the Basic-auth / Custom-Header credentials. Clearing either side reverts to an open feed."""
    user = get_user_or_none(request, db)
    if user is None:
        return JSONResponse({"error": "Not authenticated"}, status_code=401)
    feed = _owned(db, feed_id, user)
    try:
        data = await request.json()
    except Exception:
        data = {}
    field = (data.get("field") or "").strip()
    value = (data.get("value") or "").strip()
    if field == "name":
        if not value:
            return JSONResponse({"error": "Name can’t be empty."}, status_code=400)
        feed.name = value
    elif field == "auth_key":
        if value:
            feed.auth_header_key = value
        else:
            feed.auth_header_key = feed.auth_header_value = None
    elif field == "auth_value":
        if value:
            feed.auth_header_value = value
        else:  # clearing the password reverts the whole feed to open (a key alone is useless)
            feed.auth_header_key = feed.auth_header_value = None
    else:
        return JSONResponse({"error": "Unknown field."}, status_code=400)
    db.commit()
    return JSONResponse({"ok": True})


# --- Feed detail / polls / delete ------------------------------------------------------
@router.get("/feeds/{feed_id}", response_class=HTMLResponse)
def feed_detail(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feed = _owned(db, feed_id, user)
    body, _ = render_feed(feed)
    url = public_url(feed)
    ioc_cmd = (custom_csv_command(feed, url)
               if feed.type == FeedType.ioc and feed.content.get("format") == "custom_csv" else None)
    return templates.TemplateResponse(
        request,
        "feed_detail.html",
        {"feed": feed, "url": url, "preview": body, "ioc_cmd": ioc_cmd, "flash": _pop_flash(request)},
    )


@router.get("/feeds/{feed_id}/polls-fragment", response_class=HTMLResponse)
def polls_fragment(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return HTMLResponse("", status_code=401)
    feed = _owned(db, feed_id, user)
    # Count + latest few via SQL (don't load the whole — possibly huge — poll history).
    total = db.scalar(
        select(func.count()).select_from(FeedPoll).where(FeedPoll.feed_id == feed.id)
    ) or 0
    recent = db.scalars(
        select(FeedPoll)
        .where(FeedPoll.feed_id == feed.id)
        .order_by(FeedPoll.at.desc())
        .limit(POLL_PREVIEW)
    ).all()
    return templates.TemplateResponse(
        request,
        "_polls.html",
        {"polls": recent, "total": total, "last": recent[0] if recent else None},
    )


@router.post("/feeds/{feed_id}/delete")
def delete_feed_form(feed_id: int, request: Request, db: Session = Depends(get_db)):
    user = get_user_or_none(request, db)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    feed = _owned(db, feed_id, user)
    name = feed.name
    db.delete(feed)
    db.commit()
    _flash(request, f"Feed “{name}” deleted.")
    return RedirectResponse("/feeds", status_code=303)
