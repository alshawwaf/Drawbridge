"""A small async syslog receiver (UDP + TCP on one port) for Check Point's Log Exporter.

Lines are enqueued on receipt and stored off the event loop (``asyncio.to_thread``) so a burst of
firewall logs never blocks the web app. Bind failures are the caller's to handle — the app keeps
running without the receiver. Demo-scale by design (newest-N retention in the store)."""
import asyncio
import logging
from collections.abc import Callable

log = logging.getLogger("dcsim.syslog")

StoreBatchFn = Callable[[list], None]  # (list of (source_ip, transport, raw_line) tuples)
_BATCH_MAX = 500  # drain up to this many queued lines into one DB transaction


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, enqueue: Callable[[str, str, str], None]):
        self._enqueue = enqueue

    def datagram_received(self, data: bytes, addr) -> None:
        ip = addr[0] if addr else ""
        for line in data.decode("utf-8", "replace").splitlines():
            if line.strip():
                self._enqueue(ip, "udp", line)


class SyslogReceiver:
    """Listens on udp+tcp/<port>; calls ``store_cb(ip, transport, line)`` per received log line."""

    def __init__(self, port: int, store_batch: StoreBatchFn):
        self.port = port
        self.store_batch = store_batch
        self._queue: asyncio.Queue | None = None
        self._udp = None
        self._tcp: asyncio.AbstractServer | None = None
        self._consumer: asyncio.Task | None = None

    def _enqueue(self, ip: str, transport: str, line: str) -> None:
        if self._queue is None:
            return
        try:
            self._queue.put_nowait((ip, transport, line))
        except asyncio.QueueFull:
            pass  # under a flood, drop rather than block

    async def _handle_tcp(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        ip = peer[0] if peer else ""
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").strip()
                if line:
                    self._enqueue(ip, "tcp", line)
        except Exception:  # noqa: BLE001 — never let one connection break the listener
            pass
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _consume(self) -> None:
        assert self._queue is not None
        while True:
            batch = [await self._queue.get()]  # block for the first, then drain what's waiting
            while len(batch) < _BATCH_MAX:
                try:
                    batch.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            try:
                await asyncio.to_thread(self.store_batch, batch)
            except Exception:  # noqa: BLE001
                log.exception("SIEM receiver: failed to store a log batch")

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        self._queue = asyncio.Queue(maxsize=10000)
        self._udp, _ = await loop.create_datagram_endpoint(
            lambda: _UDPProtocol(self._enqueue), local_addr=("0.0.0.0", self.port))
        self._tcp = await asyncio.start_server(self._handle_tcp, "0.0.0.0", self.port)
        self._consumer = asyncio.create_task(self._consume())
        log.info("SIEM receiver listening on udp+tcp/%d", self.port)

    async def stop(self) -> None:
        if self._consumer:
            self._consumer.cancel()
        if self._udp:
            self._udp.close()
        if self._tcp:
            self._tcp.close()
            try:
                await self._tcp.wait_closed()
            except Exception:  # noqa: BLE001
                pass
