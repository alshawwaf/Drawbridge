"""Write ActivityLog entries (fire-and-forget so requests aren't delayed) with secret redaction."""
import threading

from ..db import SessionLocal
from ..models import ActivityLog

# Headers that must never be logged in the clear.
SENSITIVE_HEADERS = {"authorization", "x-chkp-sid", "cookie", "set-cookie", "proxy-authorization"}
# Body keys (any casing) whose values must be redacted.
SENSITIVE_KEYS = {"password", "pass", "secret", "token", "sid", "x-chkp-sid"}


def redact_headers(headers: dict) -> dict:
    return {k: ("(masked)" if k.lower() in SENSITIVE_HEADERS else v) for k, v in headers.items()}


def redact_body(value):
    if isinstance(value, dict):
        return {k: ("***" if k.lower() in SENSITIVE_KEYS else redact_body(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_body(v) for v in value]
    return value


def write_activity(**fields) -> None:
    def _write():
        db = SessionLocal()
        try:
            db.add(ActivityLog(**fields))
            db.commit()
        except Exception:
            db.rollback()
        finally:
            db.close()

    threading.Thread(target=_write, daemon=True).start()
