"""Runtime configuration, sourced from environment / .env (prefix DCSIM_)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DCSIM_", extra="ignore")

    app_name: str = "Drawbridge"

    # Public base URL used to build the feed URLs shown to the SE. Behind Caddy
    # this is the HTTPS domain (e.g. https://dcsim.example.com). Set via env.
    base_url: str = "http://localhost:8000"

    # Origins allowed to iframe this portal (CSP frame-ancestors). BLANK = auto: 'self' plus the parent
    # domain of base_url, so a sibling app (e.g. a dev-hub at hub.<domain>) can embed it while everything
    # else is refused. Set "'none'" to forbid all framing, or an explicit space-separated allowlist.
    # Anti-clickjacking stays on either way — this only scopes WHO may frame, never disables protection.
    frame_ancestors: str = ""

    # Cookie-signing key for portal sessions. MUST be set in production.
    # If empty, an ephemeral key is generated at startup (dev only — logs out on restart).
    session_secret: str = ""

    # Dedicated key for encrypting secrets at rest (saved gateway/DC passwords + the portal-set MCP /
    # webhook / ServiceNow secrets, AES-256-GCM). Falls back to session_secret. If both are empty, stored
    # secrets cannot be decrypted after a restart — set DCSIM_ENCRYPTION_KEY (or DCSIM_SESSION_SECRET) in
    # prod. RECOMMENDED: set DCSIM_ENCRYPTION_KEY independently of DCSIM_SESSION_SECRET — otherwise
    # rotating the session/cookie secret changes the derivation base and ORPHANS every stored secret
    # (they become undecryptable and silently fall back to env/disabled; you'd re-enter them in Settings).
    encryption_key: str = ""

    # Seed portal admin. Never hardcode a password — set DCSIM_ADMIN_PASSWORD via env.
    # If empty, a random password is generated and printed once at startup (dev convenience).
    admin_username: str = "admin"
    admin_password: str = ""

    database_url: str = "sqlite:///./data/dcsim.db"

    # Default Generic DC poll interval hint shown in the UI (seconds). Min 10 per sk167210.
    default_gdc_interval: int = 10

    # SIEM receiver: the TCP+UDP port the built-in Log Exporter listener binds. On by default (5514,
    # a high port that needs no root); set 0 to disable. Binding is best-effort — if the port is taken
    # the app still runs. For *external* gateways to reach it, the port must also be published at the
    # deployment edge (docker-compose does; on Dokploy add a TCP+UDP entrypoint). Point Check Point's
    # cp_log_export target-port here.
    syslog_port: int = 5514

    # SIEM receiver retention: keep only the newest N log records (a flooding gateway can't fill the
    # disk — older rows are trimmed). It's a live demo viewer, not a log archive.
    syslog_max_records: int = 2000

@lru_cache
def get_settings() -> Settings:
    return Settings()
