"""Minimal classic-PCAP reader and protocol/payload analyzer."""

from __future__ import annotations

import ipaddress
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .models import PacketRecord, SensitiveField


class PcapError(ValueError):
    """Raised when a capture is unsupported or malformed."""


@dataclass(slots=True, frozen=True)
class PcapInfo:
    byte_order: str
    nanosecond_resolution: bool
    link_type: int
    snaplen: int


MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\x4d\x3c\xb2\xa1": ("<", True),
    b"\xa1\xb2\x3c\x4d": (">", True),
}


def read_pcap(path: str | Path, max_packets: int | None = None) -> list[PacketRecord]:
    """Read a classic PCAP and extract TCP/UDP application payloads."""
    capture = Path(path)
    with capture.open("rb") as stream:
        header = stream.read(24)
        if len(header) != 24 or header[:4] not in MAGIC:
            raise PcapError("Expected a classic PCAP file (pcapng is not supported)")
        order, nanos = MAGIC[header[:4]]
        _, _, _, _, snaplen, link_type = struct.unpack(f"{order}HHIIII", header[4:])
        info = PcapInfo(order, nanos, link_type, snaplen)
        packets: list[PacketRecord] = []
        index = 0
        while max_packets is None or index < max_packets:
            packet_header = stream.read(16)
            if not packet_header:
                break
            if len(packet_header) != 16:
                raise PcapError("Truncated packet header")
            seconds, fraction, captured, original = struct.unpack(f"{order}IIII", packet_header)
            if captured > max(snaplen, 16 * 1024 * 1024):
                raise PcapError("Invalid captured packet length")
            raw = stream.read(captured)
            if len(raw) != captured:
                raise PcapError("Truncated packet data")
            scale = 1_000_000_000 if nanos else 1_000_000
            packets.append(_decode(index, seconds + fraction / scale, raw, original, info))
            index += 1
        return packets


def _decode(
    index: int, timestamp: float, raw: bytes, original: int, info: PcapInfo
) -> PacketRecord:
    record = PacketRecord(index, timestamp, len(raw), original, raw, raw)
    if info.link_type != 1 or len(raw) < 14:  # Ethernet only; preserve raw bytes otherwise.
        return record
    ether_type = struct.unpack("!H", raw[12:14])[0]
    offset = 14
    if ether_type == 0x8100 and len(raw) >= 18:  # 802.1Q VLAN
        ether_type = struct.unpack("!H", raw[16:18])[0]
        offset = 18
    if ether_type != 0x0800 or len(raw) < offset + 20:
        return record
    version_ihl = raw[offset]
    if version_ihl >> 4 != 4:
        return record
    ihl = (version_ihl & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl:
        return record
    protocol = raw[offset + 9]
    record.source = str(ipaddress.ip_address(raw[offset + 12 : offset + 16]))
    record.destination = str(ipaddress.ip_address(raw[offset + 16 : offset + 20]))
    transport = offset + ihl
    if protocol == 6 and len(raw) >= transport + 20:
        record.protocol = "tcp"
        record.source_port, record.destination_port = struct.unpack(
            "!HH", raw[transport : transport + 4]
        )
        data_offset = (raw[transport + 12] >> 4) * 4
        record.tcp_flags = raw[transport + 13]
        record.payload = raw[transport + data_offset :] if data_offset >= 20 else b""
    elif protocol == 17 and len(raw) >= transport + 8:
        record.protocol = "udp"
        record.source_port, record.destination_port = struct.unpack(
            "!HH", raw[transport : transport + 4]
        )
        record.payload = raw[transport + 8 :]
    else:
        record.protocol = f"ip-{protocol}"
        record.payload = raw[transport:]
    return record


def usable_seeds(packets: Iterable[PacketRecord]) -> list[bytes]:
    """Return unique non-empty application payloads while preserving order."""
    seen: set[bytes] = set()
    output: list[bytes] = []
    for packet in packets:
        if packet.payload and packet.payload not in seen:
            output.append(packet.payload)
            seen.add(packet.payload)
    return output


def detect_sensitive_fields(payload: bytes) -> list[SensitiveField]:
    """Score offsets likely to encode lengths, identifiers, delimiters, or boundaries."""
    if not payload:
        return []
    candidates: dict[tuple[int, int], tuple[float, set[str]]] = {}

    def add(offset: int, length: int, score: float, reason: str) -> None:
        key = (offset, length)
        old_score, reasons = candidates.get(key, (0.0, set()))
        reasons.add(reason)
        candidates[key] = (old_score + score, reasons)

    total = len(payload)
    for index, value in enumerate(payload):
        if index < min(8, total):
            add(index, 1, 1.0, "header")
        if value in (0, 1, 0x7F, 0x80, 0xFE, 0xFF):
            add(index, 1, 1.5, "boundary-value")
        if value in b"=:;,|&?":
            add(index, 1, 1.2, "delimiter")
        if value == total or value == max(0, total - index - 1):
            add(index, 1, 2.5, "probable-length")
    for index in range(max(0, total - 1)):
        value = int.from_bytes(payload[index : index + 2], "big")
        if value in (total, total - index - 2):
            add(index, 2, 3.0, "probable-16bit-length")
    return [
        SensitiveField(offset, length, score, tuple(sorted(reasons)))
        for (offset, length), (score, reasons) in sorted(
            candidates.items(), key=lambda item: (-item[1][0], item[0][0])
        )
    ]
