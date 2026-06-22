"""Runtime configuration, sourced from environment / .env (prefix DCSIM_)."""
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DCSIM_", extra="ignore")

    app_name: str = "Drawbridge"

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

    # SIEM receiver: the TCP+UDP port the built-in Log Exporter listener binds. On by default (5514,
    # a high port that needs no root); set 0 to disable. Binding is best-effort — if the port is taken
    # the app still runs. For *external* gateways to reach it, the port must also be published at the
    # deployment edge (docker-compose does; on Dokploy add a TCP+UDP entrypoint). Point Check Point's
    # cp_log_export target-port here.
    syslog_port: int = 5514

    # SIEM receiver retention: keep only the newest N log records (a flooding gateway can't fill the
    # disk — older rows are trimmed). It's a live demo viewer, not a log archive.
    syslog_max_records: int = 2000

    # Access automation — generic ticketing webhook (ServiceNow, Jira, Remedy, custom portal …).
    # The inbound webhook (POST /access-automation/webhook) is DISABLED unless a shared secret is set;
    # the caller must send it as the X-DCSim-Token header. Never hardcode — set via env.
    # SECURITY: this token grants policy publish on every ALLOWED management server, so treat it as a
    # top-tier secret. Optionally scope it to specific servers with DCSIM_WEBHOOK_SERVER_IDS.
    webhook_token: str = ""
    webhook_server_ids: str = ""    # comma-separated server ids the webhook may target; blank = all

    # MCP server (for n8n / LLM agents). The /mcp endpoint is DISABLED until this bearer token is set;
    # clients send it as `Authorization: Bearer <token>`. Like the webhook token it can drive policy
    # writes, so treat it as a top-tier secret. Writes are additionally gated by the mcp_allow_publish
    # setting (default OFF) — an agent can decide/preview/dry-run freely but can't publish to a live SMS
    # unless an admin turns that on. Requires the `mcp` SDK (install via Artifactory) to activate.
    mcp_token: str = ""

    # Optional BUILT-IN write-back: post the decision + rule UID to a ServiceNow incident's work notes
    # via the Table API. (Other vendors use the generic per-request `callback_url`, or just read the
    # synchronous response.) TLS verification is always on; the password is read from env (never
    # hardcoded), mirroring DCSIM_ADMIN_PASSWORD.
    servicenow_instance: str = ""   # e.g. https://dev12345.service-now.com
    servicenow_user: str = ""
    servicenow_password: str = ""
    servicenow_table: str = "incident"


@lru_cache
def get_settings() -> Settings:
    return Settings()
