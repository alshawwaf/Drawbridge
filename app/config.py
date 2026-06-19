"""Runtime configuration, sourced from environment / .env (prefix DCSIM_)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DCSIM_", extra="ignore")

    app_name: str = "Check Point Dynamic-Object Integration Simulator"

    # Public base URL used to build the feed URLs shown to the SE. Behind Caddy
    # this is the HTTPS domain (e.g. https://dcsim.example.com). Set via env.
    base_url: str = "http://localhost:8000"

    # Cookie-signing key for portal sessions. MUST be set in production.
    # If empty, an ephemeral key is generated at startup (dev only — logs out on restart).
    session_secret: str = ""

    # Dedicated key for encrypting secrets at rest (the optional saved gateway password,
    # AES-256-GCM). Falls back to session_secret. If both are empty, stored passwords cannot
    # be decrypted after a restart — set DCSIM_ENCRYPTION_KEY (or DCSIM_SESSION_SECRET) in prod.
    encryption_key: str = ""

    # Seed portal admin. Never hardcode a password — set DCSIM_ADMIN_PASSWORD via env.
    # If empty, a random password is generated and printed once at startup (dev convenience).
    admin_username: str = "admin"
    admin_password: str = ""

    database_url: str = "sqlite:///./data/dcsim.db"

    # Default Generic DC poll interval hint shown in the UI (seconds). Min 10 per sk167210.
    default_gdc_interval: int = 10

    # SIEM receiver: the TCP+UDP port the built-in Log Exporter listener binds (0 = disabled).
    # Use a high port (e.g. 5514) to avoid needing root for the privileged 514; point Check Point's
    # cp_log_export target-port here. Must also be published by docker-compose / the host firewall.
    syslog_port: int = 0


@lru_cache
def get_settings() -> Settings:
    return Settings()
