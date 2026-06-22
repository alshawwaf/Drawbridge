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


def test_parse_splunk_keyvalue():
    line = ("<134>1 2026-06-19T12:00:10Z gw-01 CheckPoint - - - action=Accept src=10.10.0.57 "
            "dst=203.0.113.12 proto=tcp service=https rule=12 origin=gw-01 msg=two words")
    p = siem.parse_line(line)
    assert p["fmt"] == "keyval"                              # Splunk/LogRhythm/RSA key=value field list
    assert p["fields"]["action"] == "Accept" and p["fields"]["src"] == "10.10.0.57"
    assert p["fields"]["msg"] == "two words" and p["host"] == "gw-01"
    assert "action=Accept" in p["summary"]


def test_parse_generic_colon_semicolon():
    line = ("<131>1 2026-06-19T12:00:13Z gw-01 CheckPoint - - - action:Drop; src:198.51.100.7; "
            "dst:10.10.0.22; proto:udp; rule:44; origin:gw-01")
    p = siem.parse_line(line)
    assert p["fmt"] == "keyval"                              # Check Point Generic key:value; field list
    assert p["fields"]["action"] == "Drop" and p["fields"]["dst"] == "10.10.0.22"
    assert p["host"] == "gw-01"


def test_one_stray_equals_stays_syslog():
    p = siem.parse_line("<134>1 2026-06-19T12:00:00Z gw-01 CheckPoint - - - reason=blocked here")
    assert p["fmt"] == "syslog"                              # a lone key=value isn't a field list


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


def test_pause_drops_received_logs():
    db = _session()
    siem.set_paused(db, True)
    try:
        assert siem.is_paused(db, fresh=True) is True
        assert siem.store_received(db, [("9.9.9.9", "udp", "<134>flood")]) == 0   # paused → dropped
        assert (db.scalar(select(func.count()).select_from(SiemLog)) or 0) == 0
    finally:
        siem.set_paused(db, False)
    assert siem.store_received(db, [("9.9.9.9", "udp", "<134>back")]) == 1        # resumed → stored
    assert siem.is_paused(db, fresh=True) is False


def test_pause_drops_then_resume_stores_and_stats_track_arrivals():
    """Regression for the recurring 'resume shows no logs' report: pause drops, resume stores AGAIN, and
    rx_stats counts every arrival (even while paused) so a network/firewall problem is distinguishable."""
    db = _session()
    siem._pause_cache.update(value=False, at=-1e9)            # isolate from other tests
    siem._rx.update(received=0, stored=0, dropped=0, last=0.0)
    item = [("10.0.0.9", "udp", siem.SAMPLE_LINES[0])]

    assert siem.store_received(db, item) == 1                 # not paused -> stored
    siem.set_paused(db, True)
    assert siem.store_received(db, item) == 0                 # paused -> dropped, nothing stored
    siem.set_paused(db, False)
    assert siem.store_received(db, item) == 1                 # RESUME -> stores again (the reported bug)

    assert db.scalar(select(func.count()).select_from(SiemLog)) == 2   # the two non-paused lines
    st = siem.rx_stats()
    assert st["received"] == 3 and st["stored"] == 2 and st["dropped"] == 1 and st["last"] > 0
