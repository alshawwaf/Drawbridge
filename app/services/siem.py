"""Parse + store log lines from Check Point's Log Exporter (the built-in SIEM receiver).

Log Exporter can emit syslog, CEF, LEEF, or JSON over TCP/UDP. ``parse_line`` strips the optional
syslog PRI/header and best-effort extracts a format, severity, host, one-line summary, and a field
map; the raw line is always kept. Tolerant by design — a line it can't classify is stored as raw.
"""
import json
import re
import time

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import AppState, SiemLog

_SEVERITY_NAMES = ["emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"]


def _max_records() -> int:
    """Newest-N retention cap — a flooding gateway can't grow the table without bound. Admin-tunable
    from the Settings page (``siem_max_records``), falling back to the env default; 0 = unlimited (the
    background retention sweep still applies whatever cap is configured)."""
    cap = 0
    try:
        from .app_settings import get
        cap = int(get("siem_max_records"))
    except Exception:  # noqa: BLE001 — never let a settings read break the hot store path
        cap = 0
    if cap <= 0:
        cap = get_settings().syslog_max_records
    return max(0, cap)


def _parse_ext(ext: str) -> dict:
    """CEF/LEEF extension: space-separated key=value, where values may contain spaces. Split only on
    whitespace that precedes a ``key=`` token so 'msg=two words act=Accept' parses correctly."""
    out: dict = {}
    for part in re.split(r"\s(?=[A-Za-z0-9_]+=)", ext.strip()):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def _parse_cef(s: str) -> dict:
    """s starts with 'CEF:'. Header: CEF:Version|Vendor|Product|Version|SignatureID|Name|Severity|Ext."""
    parts = re.split(r"(?<!\\)\|", s[4:], maxsplit=7)
    parts += [""] * (8 - len(parts))
    version, vendor, product, dev_ver, sig_id, name, severity, ext = (p.replace("\\|", "|") for p in parts[:8])
    fields = {"vendor": vendor, "product": product, "device_version": dev_ver,
              "signature_id": sig_id, "name": name, "cef_version": version}
    fields.update(_parse_ext(ext))
    summary = name.strip()
    extras = [f"{k}={fields[k]}" for k in ("src", "dst", "suser", "act", "msg") if fields.get(k)]
    if extras:
        summary = (summary + " · " + " ".join(extras)).strip(" ·")
    return {"fields": fields, "severity": severity.strip(), "summary": summary or s[:160]}


def _parse_leef(s: str) -> dict:
    """s starts with 'LEEF:'. Header: LEEF:Version|Vendor|Product|Version|EventID|[Delim]then attrs."""
    parts = s[5:].split("|")
    fields = {"leef_version": parts[0] if parts else "",
              "vendor": parts[1] if len(parts) > 1 else "",
              "product": parts[2] if len(parts) > 2 else "",
              "device_version": parts[3] if len(parts) > 3 else "",
              "event_id": parts[4] if len(parts) > 4 else ""}
    attrs = "|".join(parts[5:]) if len(parts) > 5 else ""
    if "\t" in attrs:  # LEEF default delimiter is a tab
        for kv in attrs.split("\t"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                fields[k.strip()] = v.strip()
    else:
        fields.update(_parse_ext(attrs))
    summary = fields["event_id"].strip()
    extras = [f"{k}={fields[k]}" for k in ("src", "dst", "usrName", "sev") if fields.get(k)]
    if extras:
        summary = (summary + " · " + " ".join(extras)).strip(" ·")
    return {"fields": fields, "summary": summary or s[:160]}


def _json_summary(obj: dict) -> str:
    keys = [k for k in ("action", "act", "src", "dst", "service", "rule", "msg", "product") if obj.get(k)]
    if keys:
        return " ".join(f"{k}={obj[k]}" for k in keys)[:380]
    return ", ".join(f"{k}={v}" for k, v in list(obj.items())[:4])[:380]


def _kv_pairs(body: str) -> dict:
    """Parse a prefix-less field-list format: Splunk / LogRhythm / RSA emit ``key=value key2=value2``
    (values may be quoted or contain spaces); Check Point's **Generic** format emits
    ``key:value; key2:value2;``. Returns whichever separator yields the richer field map."""
    fields = body.rsplit(" - - - ", 1)[-1]                  # drop the RFC5424 header ('… CheckPoint - - -')
    eq = _parse_ext(fields)                                 # 'key=value' (whitespace-before-key= split)
    semi: dict = {}
    if ";" in fields:
        for part in fields.split(";"):
            k, sep, v = part.strip().partition(":")
            k = k.strip()
            if sep and v.strip() and re.fullmatch(r"[A-Za-z0-9_.\-]+", k):
                semi[k] = v.strip()
    return semi if len(semi) > len(eq) else eq


def _kv_summary(f: dict) -> str:
    keys = [k for k in ("action", "act", "src", "dst", "service", "proto", "rule", "msg") if f.get(k)]
    if keys:
        return " ".join(f"{k}={f[k]}" for k in keys)[:380]
    return " ".join(f"{k}={v}" for k, v in list(f.items())[:6])[:380]


def _syslog_host_msg(body: str) -> tuple[str, str]:
    """RFC3164: 'Mmm dd hh:mm:ss host tag: msg' → (host, msg). Best-effort."""
    m = re.match(r"^[A-Z][a-z]{2}\s+\d+\s+[\d:]+\s+(\S+)\s+(.*)$", body)
    if m:
        return m.group(1), m.group(2).strip()[:380]
    return "", body[:380]


def parse_line(raw: str) -> dict:
    """Classify and structure a single log line. Always returns {fmt, severity, host, summary, fields}."""
    raw = (raw or "").strip()
    out = {"fmt": "raw", "severity": "", "host": "", "summary": raw[:380], "fields": {}}
    if not raw:
        out["summary"] = ""
        return out
    body = raw
    m = re.match(r"^<(\d+)>\s*(.*)$", body, re.S)  # strip syslog priority
    if m:
        out["severity"] = _SEVERITY_NAMES[int(m.group(1)) % 8]
        body = m.group(2)

    idx = body.find("CEF:")
    if idx != -1:
        cef = _parse_cef(body[idx:])
        out.update(fmt="cef", host=_header_host(body[:idx]), fields=cef["fields"], summary=cef["summary"])
        out["severity"] = cef["severity"] or out["severity"]
        return out

    idx = body.find("LEEF:")
    if idx != -1:
        leef = _parse_leef(body[idx:])
        out.update(fmt="leef", host=_header_host(body[:idx]), fields=leef["fields"], summary=leef["summary"])
        return out

    brace = body.find("{")  # JSON may sit after a syslog header ("1 ts host - {...}")
    if brace != -1:
        try:
            obj = json.loads(body[brace:])
            if isinstance(obj, dict):
                out.update(fmt="json", fields=obj, summary=_json_summary(obj))
                out["severity"] = str(obj.get("severity") or obj.get("level") or out["severity"])
                out["host"] = str(obj.get("origin") or obj.get("host") or _header_host(body[:brace]))
                return out
        except ValueError:
            pass

    kv = _kv_pairs(body)   # Splunk / LogRhythm / RSA (key=value) or Check Point Generic (key:value;)
    if len(kv) >= 3:
        out.update(fmt="keyval", fields=kv, summary=_kv_summary(kv),
                   host=(kv.get("origin") or kv.get("hostname") or kv.get("host")
                         or _header_host(" ".join(body.split()[:4]))))   # leading syslog-header tokens
        return out

    out["fmt"] = "syslog"
    out["host"], out["summary"] = _syslog_host_msg(body)
    return out


def _header_host(header: str) -> str:
    """Pull the hostname from a syslog header preceding CEF/LEEF/JSON. RFC5424 puts it third
    (VERSION TIMESTAMP HOSTNAME …); otherwise take the last real token, ignoring '-' placeholders."""
    raw_toks = header.split()
    toks = [t for t in raw_toks if t and t != "-"]
    if not toks:
        return ""
    if raw_toks and raw_toks[0] == "1" and len(toks) >= 3:
        return toks[2]
    return toks[-1]


def _to_record(source_ip: str, transport: str, raw: str) -> SiemLog:
    p = parse_line(raw)
    return SiemLog(source_ip=source_ip or "", transport=transport, fmt=p["fmt"],
                   severity=str(p["severity"])[:24], host=(p["host"] or "")[:120],
                   summary=(p["summary"] or "")[:400], fields=p["fields"] or {}, raw=(raw or "")[:8000])


def store_log(db: Session, source_ip: str, transport: str, raw: str) -> SiemLog:
    """Parse + persist one line (used by the 'Send test log' button); trims to the newest N."""
    log = _to_record(source_ip, transport, raw)
    db.add(log)
    db.commit()
    _trim(db)
    return log


def store_batch(db: Session, items: list[tuple[str, str, str]]) -> int:
    """Parse + persist a batch of (source_ip, transport, raw) in one transaction — the listener's
    hot path under a log flood, so it's one commit + one trim per batch, not per line."""
    if not items:
        return 0
    db.add_all([_to_record(ip, transport, raw) for ip, transport, raw in items])
    db.commit()
    _trim(db)
    return len(items)


# --- admin Pause toggle: drop the live feed without tearing down the listener ----------------
# Stored in the DB (AppState) so a Pause/Resume from any uvicorn worker or Swarm replica reaches the
# replica running the listener — an in-memory flag isn't shared and made Resume look broken. The page
# reads it fresh; the listener's hot path reads a ~2s cache so it isn't a DB hit per batch.
_PAUSE_KEY = "siem_paused"
_pause_cache = {"value": False, "at": -1e9}


def is_paused(db: Session, fresh: bool = False) -> bool:
    """``fresh=True`` for page renders (always accurate); cached for the listener's per-batch path."""
    now = time.monotonic()
    if fresh or (now - _pause_cache["at"]) > 2.0:
        row = db.get(AppState, _PAUSE_KEY)
        _pause_cache["value"] = bool(row and row.value == "1")
        _pause_cache["at"] = now
    return _pause_cache["value"]


def set_paused(db: Session, value: bool) -> None:
    row = db.get(AppState, _PAUSE_KEY)
    if row is None:
        db.add(AppState(key=_PAUSE_KEY, value="1" if value else "0"))
    else:
        row.value = "1" if value else "0"
    db.commit()
    _pause_cache.update(value=bool(value), at=time.monotonic())   # same-process consistency, no wait


# Live receiver activity (process-local; the listener runs in one process on this single-worker deploy).
# Counts EVERY line that reaches the listener — incremented before the pause check — so the page can show
# whether traffic is actually arriving. That's the tell that separates "nothing is reaching us" (a
# network / host-firewall problem — see the external-UDP trap) from "arriving but paused/stored".
_rx = {"received": 0, "stored": 0, "dropped": 0, "last": 0.0}


def rx_stats() -> dict:
    return dict(_rx)


def store_received(db: Session, items: list[tuple[str, str, str]]) -> int:
    """The network listener's entrypoint. When the admin has paused, the batch is dropped (the
    listener keeps draining its queue so nothing backs up); only manual 'Send test log' still writes."""
    n_in = len(items)
    _rx["received"] += n_in
    _rx["last"] = time.time()
    if is_paused(db):
        _rx["dropped"] += n_in           # arriving but intentionally dropped — NOT a network problem
        return 0
    n = store_batch(db, items)
    _rx["stored"] += n
    return n


def _trim(db: Session) -> None:
    """Delete everything older than the newest N by primary key — an indexed range delete that fires
    only when over cap (cheap even under load), keeping the table (and disk) bounded."""
    cap = _max_records()
    if cap <= 0:               # unlimited — the per-batch trim is disabled
        return
    n = db.scalar(select(func.count()).select_from(SiemLog)) or 0
    if n > cap:
        max_id = db.scalar(select(func.max(SiemLog.id))) or 0
        db.execute(delete(SiemLog).where(SiemLog.id <= max_id - cap))
        db.commit()


# Sample lines for the viewer's "Send test log" button — what Check Point Log Exporter emits, so the
# receiver can be demoed without a real gateway pointed at it yet.
SAMPLE_LINES = [
    ("<134>1 2026-06-19T12:00:01Z gw-01 CheckPoint - - - CEF:0|Check Point|VPN-1 & FireWall-1|R82|"
     "Accept|Firewall|3|src=10.10.0.55 dst=203.0.113.10 spt=51514 dpt=443 proto=tcp act=Accept "
     "rule=12 layer_name=Network msg=Demo accepted connection"),
    ("<131>1 2026-06-19T12:00:04Z gw-01 CheckPoint - - - CEF:0|Check Point|VPN-1 & FireWall-1|R82|"
     "Drop|Firewall|7|src=198.51.100.9 dst=10.10.0.21 dpt=22 proto=tcp act=Drop rule=44 "
     "layer_name=Network msg=Demo dropped SSH from blocklisted host"),
    ('<134>1 2026-06-19T12:00:07Z gw-01 CheckPoint - - - {"action":"Accept","src":"10.10.0.56",'
     '"dst":"203.0.113.11","service":"https","rule":"12","product":"Firewall","origin":"gw-01"}'),
    # Splunk / LogRhythm / RSA — prefix-less key=value field list
    ("<134>1 2026-06-19T12:00:10Z gw-01 CheckPoint - - - action=Accept src=10.10.0.57 dst=203.0.113.12 "
     "proto=tcp service=https rule=12 product=Firewall origin=gw-01 msg=Demo Splunk-format connection"),
    # Check Point Generic — key:value; field list
    ("<131>1 2026-06-19T12:00:13Z gw-01 CheckPoint - - - action:Drop; src:198.51.100.7; dst:10.10.0.22; "
     "proto:udp; rule:44; product:Firewall; origin:gw-01; msg:Demo Generic-format drop"),
    # With the Attachments fields (SmartView links + Log Attachment ID) Log Exporter can append
    ("<134>1 2026-06-19T12:00:16Z gw-01 CheckPoint - - - CEF:0|Check Point|VPN-1 & FireWall-1|R82|"
     "Accept|Firewall|3|src=10.10.0.58 dst=203.0.113.13 proto=tcp act=Accept rule=12 origin=gw-01 "
     "logId=1a2b-3c4d-5e6f logDetailsLink=https://smartconsole.example/smartview/#/log/1a2b-3c4d-5e6f "
     "logAttachmentLink=https://smartconsole.example/smartview/attachment/1a2b-3c4d-5e6f "
     "msg=Demo log with SmartView attachment links"),
]
