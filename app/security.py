"""Password hashing (stdlib PBKDF2-HMAC-SHA256), token generation, and auth deps."""
import base64
import hashlib
import hmac
import os
import secrets

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from .db import get_db
from .models import User

_ALGO = "pbkdf2_sha256"
_ITERATIONS = 200_000


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"{_ALGO}${_ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iters, salt_b64, dk_b64 = stored.split("$")
        if algo != _ALGO:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iters))
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def new_feed_token(nbytes: int = 24) -> str:
    """Long, URL-safe, unguessable token used as the public feed path segment."""
    return secrets.token_urlsafe(nbytes)


def get_user_or_none(request: Request, db: Session) -> User | None:
    uid = request.session.get("uid")
    if not uid:
        return None
    return db.get(User, uid)


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Dependency for authenticated JSON API endpoints (raises 401)."""
    user = get_user_or_none(request, db)
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return user
