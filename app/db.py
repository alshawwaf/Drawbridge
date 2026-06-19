"""Database engine, session factory, and schema bootstrap (SQLAlchemy 2.0)."""
import os
from collections.abc import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_settings = get_settings()
_connect_args = {"check_same_thread": False} if _settings.database_url.startswith("sqlite") else {}
engine = create_engine(_settings.database_url, connect_args=_connect_args)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


def get_db() -> Iterator[Session]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    # Ensure the SQLite directory exists before creating tables.
    url = _settings.database_url
    if url.startswith("sqlite:///"):
        path = url.replace("sqlite:///", "", 1)
        directory = os.path.dirname(path)
        if directory:
            os.makedirs(directory, exist_ok=True)
    # Import models so they register on the metadata before create_all.
    from . import models  # noqa: F401

    Base.metadata.create_all(engine)
    _ensure_columns()


# Additive, idempotent column migrations for SQLite (no Alembic): create_all won't add a column to an
# already-existing table, so columns introduced later are added here on boot.
_ADDED_COLUMNS = {"gateways": {"auto_trust": "BOOLEAN DEFAULT 1"}}


def _ensure_columns() -> None:
    insp = inspect(engine)
    names = set(insp.get_table_names())
    for table, cols in _ADDED_COLUMNS.items():
        if table not in names:
            continue
        existing = {c["name"] for c in insp.get_columns(table)}
        for col, ddl in cols.items():
            if col not in existing:
                with engine.begin() as conn:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}"))
