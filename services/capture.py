from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from threading import Event, Lock, Thread
from time import monotonic

WINDOW_SECONDS = 10
PACKET_LIMIT = 50_000
SESSION_LEASE = 150


@dataclass(frozen=True)
class PacketEvent:
    seen: float
    src_ip: str
    dst_ip: str
    protocol: str
    dst_port: int | None
    size: int
    tcp_syn: bool
    time: str


def capture_interfaces() -> dict[str, str]:
    from scapy.all import conf

    conf.ifaces.reload()
    conf.route.resync()
    default, _, _ = conf.route.route("0.0.0.0")
    default = getattr(default, "network_name", default)

    ranked = []
    for iface in conf.ifaces.values():
        flags = str(iface.flags).split("+")
        name = iface.description or iface.name
        if "LOOPBACK" in flags:
            rank, status = 3, "Loopback"
        elif "DISCONNECTED" in flags:
            rank, status = 4, "Disconnected"
        elif iface.network_name == default:
            rank, status = 0, "Default route"
        elif iface.ip:
            rank, status = 1, ""
        else:
            rank, status = 2, ""
        if status:
            name = f"{name} ({status})"
        ranked.append((rank, name, iface.network_name))
    return {key: name for _, name, key in sorted(ranked)}


class LiveCapture:
    def __init__(self, interface: str, auth_seconds: float):
        self.interface = interface
        self._packets: deque[PacketEvent] = deque(maxlen=PACKET_LIMIT)
        self._lock = Lock()
        self._stop = Event()
        self._ready = Event()
        self._deadline = monotonic() + min(SESSION_LEASE, max(0, auth_seconds))
        self._total = 0
        self._started_at = None
        self.error: str | None = None
        self._thread = Thread(target=self._run, name="netra-capture", daemon=True)
        self._thread.start()

    @property
    def active(self) -> bool:
        return self._thread.is_alive() and not self._stop.is_set()

    @property
    def ready(self) -> bool:
        return self._ready.is_set()

    def renew(self, auth_seconds: float) -> None:
        now = monotonic()
        with self._lock:
            if now <= self._deadline:
                self._deadline = now + min(SESSION_LEASE, max(0, auth_seconds))

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)

    def _run(self) -> None:
        try:
            from scapy.all import IP, TCP, UDP, IPv6, conf, sniff

            def observe(packet):
                network = packet.getlayer(IP) or packet.getlayer(IPv6)
                if network is None:
                    return
                transport = network.payload
                while network.version == 6 and transport.__class__.__name__.startswith("IPv6ExtHdr"):
                    transport = transport.payload
                tcp = isinstance(transport, TCP)
                udp = isinstance(transport, UDP)
                event = PacketEvent(
                    seen=monotonic(),
                    src_ip=network.src,
                    dst_ip=network.dst,
                    protocol="TCP" if tcp else "UDP" if udp else ("IPv6" if network.version == 6 else "IPv4"),
                    dst_port=transport.dport if tcp or udp else None,
                    size=getattr(packet, "wirelen", None) or len(packet),
                    tcp_syn=tcp and int(transport.flags) & 0x12 == 0x02,
                    time=datetime.fromtimestamp(float(packet.time), timezone.utc).isoformat(timespec="milliseconds"),
                )
                with self._lock:
                    self._packets.append(event)
                    self._total += 1

            if not conf.use_pcap:
                raise RuntimeError("Npcap could not be loaded.")
            with conf.L2listen(iface=self.interface, promisc=False) as socket:
                self._started_at = monotonic()
                self._ready.set()
                while not self._stop.is_set() and monotonic() < self._deadline:
                    sniff(opened_socket=socket, store=False, prn=observe, timeout=1,
                          stop_filter=lambda _: self._stop.is_set())
        except Exception as exc:
            self.error = f"{exc}. Check the adapter and Npcap permissions."

    def snapshot(self, preview_rows: int) -> tuple[list[dict], list[dict], int, bool]:
        with self._lock:
            now = monotonic()
            packets = list(self._packets)
            total = self._total
        cutoff = now - WINDOW_SECONDS
        saturated = len(packets) == PACKET_LIMIT and packets[0].seen >= cutoff
        bytes_by_source = defaultdict(int)
        ports_by_pair = defaultdict(set)
        last_by_source = {}
        for event in reversed(packets):
            if event.seen < cutoff:
                break
            bytes_by_source[event.src_ip] += event.size
            last_by_source.setdefault(event.src_ip, event.time)
            if event.tcp_syn and event.dst_port is not None:
                ports_by_pair[event.src_ip, event.dst_ip].add(event.dst_port)

        max_ports = defaultdict(int)
        for (source, _), ports in ports_by_pair.items():
            max_ports[source] = max(max_ports[source], len(ports))
        elapsed = max(1, min(WINDOW_SECONDS, now - (self._started_at or now)))
        metrics = [
            {"time": last_by_source[ip], "src_ip": ip, "ports_scanned": max_ports[ip],
             "traffic_mbps": size * 8 / elapsed / 1_000_000}
            for ip, size in bytes_by_source.items()
        ]
        preview = [
            {"time": event.time, "src_ip": event.src_ip, "dst_ip": event.dst_ip,
             "protocol": event.protocol, "dst_port": event.dst_port, "bytes": event.size}
            for event in reversed(packets[-preview_rows:])
        ]
        return metrics, preview, total, saturated
