"""Application entrypoint: wiring, session middleware, DB bootstrap, admin seed."""
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
from .routers import activity, dynamic_layers, feeds, gateways, gaia_mock, serve, ui
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


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    init_db()
    _seed_admin(settings)
    yield


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
    app.add_middleware(SessionMiddleware, secret_key=session_secret, same_site="lax")
    app.add_middleware(ActivityLogMiddleware)

    app.include_router(ui.router)
    app.include_router(feeds.router)
    app.include_router(serve.router)
    app.include_router(gaia_mock.router)
    app.include_router(dynamic_layers.router)
    app.include_router(gateways.router)
    app.include_router(activity.router)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
