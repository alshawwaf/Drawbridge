"""Application entrypoint: wiring, session middleware, DB bootstrap, admin seed."""
import asyncio
import logging
import secrets
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import select
from starlette.middleware.sessions import SessionMiddleware

from .config import get_settings
from .db import SessionLocal, init_db
from .models import User
from .middleware import ActivityLogMiddleware
from .routers import (
    access_automation, aci_mock, activity, datacenters, dynamic_layers, exports, feeds, gateways,
    gaia_mock, kubernetes_mock, mgmt, notifications, nsxt_mock, nutanix_mock, openstack_mock,
    proxmox_mock, scenarios, serve, settings as settings_router, siem, ui, vcenter_mock,
)
from .security import hash_password


def _seed_admin(settings) -> None:
    with SessionLocal() as db:
        if db.scalar(select(User).where(User.username == settings.admin_username)):
            return
        password = settings.admin_password or secrets.token_urlsafe(12)
        db.add(User(username=settings.admin_username, password_hash=hash_password(password)))
        db.commit()
        if not settings.admin_password:
            banner = "=" * 64
            print(banner, file=sys.stderr)
            print(f"  Portal admin created:  {settings.admin_username} / {password}", file=sys.stderr)
            print("  Set DCSIM_ADMIN_PASSWORD to pin your own password.", file=sys.stderr)
            print(banner, file=sys.stderr)


async def _start_siem_receiver(settings):
    """Start the Log Exporter / SIEM receiver if a port is configured. Best-effort: a bind failure
    (port in use / not permitted) logs a warning and the app continues without it."""
    if not settings.syslog_port or settings.syslog_port <= 0:
        return None
    from .services import siem
    from .services.syslog_listener import SyslogReceiver

    def store_batch(items: list) -> None:
        with SessionLocal() as db:
            siem.store_received(db, items)   # honors the admin Pause toggle (drops the flood while paused)

    receiver = SyslogReceiver(settings.syslog_port, store_batch)
    try:
        await receiver.start()
    except OSError as exc:
        print(f"WARNING: SIEM receiver could not bind port {settings.syslog_port}: {exc}", file=sys.stderr)
        return None
    return receiver


async def _retention_loop():
    """Storage guardrail: periodically trim the Activity log + SIEM tables to the admin-configured caps
    so a long-running demo can't fill the disk. Defensive — an iteration failure is logged and the loop
    continues; the interval is read live so a Settings change takes effect on the next pass."""
    from .services import app_settings, retention
    await asyncio.sleep(20)   # let startup settle; the first pass also clears any pre-existing backlog
    while True:
        try:
            await asyncio.to_thread(retention.run_once)
        except Exception:  # noqa: BLE001 — housekeeping must never crash the app
            logging.getLogger("dcsim.retention").exception("retention loop iteration failed")
        try:
            interval = max(1, int(app_settings.get("retention_sweep_min"))) * 60
        except Exception:  # noqa: BLE001
            interval = 300
        await asyncio.sleep(interval)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db()
    _seed_admin(settings)
    receiver = await _start_siem_receiver(settings)
    retention_task = asyncio.create_task(_retention_loop())
    from . import mcp_server                          # run the mounted /mcp app's session manager (no-op
    try:                                              # if MCP isn't mounted)
        async with mcp_server.mcp_lifespan(app):
            yield
    finally:
        retention_task.cancel()
        if receiver is not None:
            await receiver.stop()
        from .services.mgmt_api import close_pool   # log out pooled read sessions on shutdown
        close_pool()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, lifespan=lifespan)

    session_secret = settings.session_secret
    if not session_secret:
        session_secret = secrets.token_urlsafe(32)
        print(
            "WARNING: DCSIM_SESSION_SECRET not set — using an ephemeral key "
            "(sessions drop on restart). Set it in production.",
            file=sys.stderr,
        )
    app.add_middleware(SessionMiddleware, secret_key=session_secret, same_site="lax",
                       https_only=settings.base_url.startswith("https"), max_age=14 * 24 * 3600)
    app.add_middleware(ActivityLogMiddleware)

    app.include_router(ui.router)
    app.include_router(feeds.router)
    app.include_router(serve.router)
    app.include_router(gaia_mock.router)
    app.include_router(dynamic_layers.router)
    app.include_router(gateways.router)
    app.include_router(openstack_mock.router)
    app.include_router(vcenter_mock.router)
    app.include_router(kubernetes_mock.router)  # before nsxt: its /api/v1/{nodes,pods,…} are explicit,
    app.include_router(nsxt_mock.router)        # NSX-T's /api/v1/{rest} catch-all handles the rest

    app.include_router(proxmox_mock.router)
    app.include_router(aci_mock.router)
    app.include_router(nutanix_mock.router)
    app.include_router(datacenters.router)
    app.include_router(scenarios.router)
    app.include_router(activity.router)
    app.include_router(siem.router)
    app.include_router(mgmt.router)
    app.include_router(access_automation.router)
    app.include_router(settings_router.router)
    app.include_router(notifications.router)
    app.include_router(exports.router)

    # MCP server for n8n / LLM agents — mounted at /mcp only when the SDK is installed (Artifactory) AND
    # DCSIM_MCP_TOKEN is set. Otherwise it's silently absent; the rest of the portal is unaffected.
    try:
        from . import mcp_server
        mcp_app = mcp_server.build_mcp_app(settings.mcp_token)
        if mcp_app is not None:
            app.mount("/mcp", mcp_app)
    except Exception:  # noqa: BLE001 — never let the optional MCP mount break app startup
        pass

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
