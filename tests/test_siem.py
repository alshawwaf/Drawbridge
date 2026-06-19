"""SIEM receiver: the Log Exporter line parser (syslog / CEF / LEEF / JSON) and the store + trim."""
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app import models  # noqa: F401
from app.db import Base
from app.models import SiemLog
from app.services import siem


def _session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False)()


def test_parse_cef_extracts_header_and_extension():
    line = ("<134>1 2026-06-19T12:00:01Z gw-01 CheckPoint - - - CEF:0|Check Point|VPN-1 & FireWall-1|R82|"
            "Accept|Firewall|3|src=10.10.0.55 dst=203.0.113.10 dpt=443 act=Accept msg=accepted connection")
    p = siem.parse_line(line)
    assert p["fmt"] == "cef"
    assert p["fields"]["vendor"] == "Check Point" and p["fields"]["name"] == "Firewall"
    assert p["fields"]["src"] == "10.10.0.55" and p["fields"]["act"] == "Accept"
    assert p["fields"]["msg"] == "accepted connection"        # value-with-spaces parsed correctly
    assert p["host"] == "CheckPoint" or p["host"] == "gw-01"  # last header token
    assert "Firewall" in p["summary"] and "src=10.10.0.55" in p["summary"]


def test_parse_leef_tab_delimited():
    line = "<134>LEEF:1.0|Check Point|Firewall|R82|Accept|\tsrc=10.0.0.1\tdst=10.0.0.2\tusrName=alice"
    p = siem.parse_line(line)
    assert p["fmt"] == "leef"
    assert p["fields"]["vendor"] == "Check Point" and p["fields"]["event_id"] == "Accept"
    assert p["fields"]["src"] == "10.0.0.1" and p["fields"]["usrName"] == "alice"


def test_parse_json_line():
    line = '<134>1 2026-06-19T12:00:07Z gw-01 - {"action":"Drop","src":"1.2.3.4","origin":"gw-9","severity":"high"}'
    p = siem.parse_line(line)
    assert p["fmt"] == "json"
    assert p["fields"]["action"] == "Drop" and p["host"] == "gw-9" and p["severity"] == "high"


def test_parse_priority_maps_to_severity():
    p = siem.parse_line("<131>plain syslog message here")   # 131 % 8 == 3 → err
    assert p["fmt"] == "syslog" and p["severity"] == "err"


def test_parse_empty_and_garbage_are_safe():
    assert siem.parse_line("")["fmt"] == "raw"
    assert siem.parse_line("not a known format at all")["fmt"] == "syslog"


def test_store_persists_parsed_fields():
    db = _session()
    log = siem.store_log(db, "10.0.0.9", "udp", siem.SAMPLE_LINES[0])
    assert log.fmt == "cef" and log.transport == "udp" and log.source_ip == "10.0.0.9"
    assert log.fields.get("act") == "Accept" and log.raw.startswith("<134>")


def test_listener_receives_udp_and_tcp():
    import asyncio
    import socket

    from app.services.syslog_listener import SyslogReceiver
    received = []

    async def go():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        rx = SyslogReceiver(port, received.extend)  # store callback now takes a batch (list of tuples)
        await rx.start()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"<134>udp hello\n", ("127.0.0.1", port))
        sock.close()
        _, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"<134>tcp hello\n")
        await writer.drain()
        writer.close()
        await asyncio.sleep(0.4)  # let the consumer drain the queue
        await rx.stop()

    asyncio.run(go())
    assert {t for _, t, _ in received} == {"udp", "tcp"}   # items are (ip, transport, line)


def test_store_trims_to_cap(monkeypatch):
    monkeypatch.setattr(siem, "_max_records", lambda: 5)
    db = _session()
    for i in range(12):
        siem.store_log(db, "1.1.1.1", "tcp", f"<134>msg {i}")
    assert (db.scalar(select(func.count()).select_from(SiemLog)) or 0) == 5


def test_store_batch_persists_and_trims(monkeypatch):
    monkeypatch.setattr(siem, "_max_records", lambda: 5)
    db = _session()
    n = siem.store_batch(db, [("1.1.1.1", "udp", f"<134>line {i}") for i in range(12)])
    assert n == 12  # all parsed + inserted in one transaction
    assert (db.scalar(select(func.count()).select_from(SiemLog)) or 0) == 5  # then trimmed to the cap
