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


PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
_MAX_CAPTURED = 16 * 1024 * 1024


def read_pcap(path: str | Path, max_packets: int | None = None) -> list[PacketRecord]:
    """Read a classic PCAP or PCAPNG capture and extract TCP/UDP payloads."""
    capture = Path(path)
    with capture.open("rb") as stream:
        header = stream.read(24)
        if len(header) < 4:
            raise PcapError("Expected a PCAP or PCAPNG capture file")
        if header[:4] == PCAPNG_MAGIC:
            stream.seek(0)
            return _read_pcapng(stream, max_packets)
        if header[:4] not in MAGIC or len(header) != 24:
            raise PcapError("Expected a classic PCAP or PCAPNG capture file")
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
            if captured > max(snaplen, _MAX_CAPTURED):
                raise PcapError("Invalid captured packet length")
            raw = stream.read(captured)
            if len(raw) != captured:
                raise PcapError("Truncated packet data")
            scale = 1_000_000_000 if nanos else 1_000_000
            packets.append(_decode(index, seconds + fraction / scale, raw, original, info))
            index += 1
        return packets


def _read_pcapng(stream, max_packets: int | None) -> list[PacketRecord]:
    """Read a PCAPNG capture (SHB/IDB/EPB/SPB blocks) into packet records."""
    order = "<"
    interfaces: list[tuple[int, int, float]] = []  # (link_type, snaplen, ts_divisor)
    packets: list[PacketRecord] = []
    index = 0
    while max_packets is None or index < max_packets:
        head = stream.read(8)
        if not head:
            break
        if len(head) < 8:
            raise PcapError("Truncated PCAPNG block header")
        block_type = head[:4]
        if block_type == PCAPNG_MAGIC:  # Section Header Block carries the byte order.
            magic = stream.read(4)
            order = ">" if magic == b"\x1a\x2b\x3c\x4d" else "<"
            total = struct.unpack(f"{order}I", head[4:8])[0]
            if total < 12 or total > _MAX_CAPTURED:
                raise PcapError("Invalid PCAPNG section header length")
            stream.read(total - 12)  # skip rest of SHB (version, section length, options, trailer)
            interfaces.clear()
            continue
        total = struct.unpack(f"{order}I", head[4:8])[0]
        if total < 12 or total > _MAX_CAPTURED:
            raise PcapError("Invalid PCAPNG block length")
        body = stream.read(total - 12)
        if len(body) != total - 12 or len(stream.read(4)) != 4:
            raise PcapError("Truncated PCAPNG block")
        tid = struct.unpack(f"{order}I", block_type)[0]
        if tid == 0x00000001:  # Interface Description Block
            link_type, snaplen = struct.unpack(f"{order}HxxI", body[:8])
            interfaces.append((link_type, snaplen, _tsresol_divisor(body[8:], order)))
        elif tid in (0x00000006, 0x00000003):  # Enhanced / Simple Packet Block
            rec = _pcapng_packet(tid, body, order, interfaces, index)
            if rec is not None:
                packets.append(rec)
                index += 1
    if not interfaces and not packets:
        raise PcapError("PCAPNG file has no interface or packet blocks")
    return packets


def _tsresol_divisor(options: bytes, order: str) -> float:
    """Return the timestamp divisor from an IDB if_tsresol option (default microseconds)."""
    pos = 0
    while pos + 4 <= len(options):
        code, length = struct.unpack(f"{order}HH", options[pos : pos + 4])
        value = options[pos + 4 : pos + 4 + length]
        if code == 0:  # opt_endofopt
            break
        if code == 9 and length >= 1:  # if_tsresol
            raw = value[0]
            return float(2 ** (raw & 0x7F)) if raw & 0x80 else float(10 ** raw)
        pos += 4 + length + (-length % 4)  # options are padded to 32-bit boundaries
    return 1_000_000.0


def _pcapng_packet(
    tid: int, body: bytes, order: str, interfaces: list[tuple[int, int, float]], index: int
) -> PacketRecord | None:
    if tid == 0x00000006:  # Enhanced Packet Block
        if len(body) < 20:
            raise PcapError("Truncated PCAPNG enhanced packet block")
        if_id, ts_high, ts_low, captured, original = struct.unpack(f"{order}IIIII", body[:20])
        raw = body[20 : 20 + captured]
        link_type, _, divisor = interfaces[if_id] if if_id < len(interfaces) else (1, 0, 1e6)
        timestamp = ((ts_high << 32) | ts_low) / (divisor or 1e6)
    else:  # Simple Packet Block uses the first interface and has no per-packet length/time.
        if len(body) < 4 or not interfaces:
            return None
        original = struct.unpack(f"{order}I", body[:4])[0]
        link_type, snaplen, _ = interfaces[0]
        captured = min(original, snaplen) if snaplen else original
        raw = body[4 : 4 + captured]
        timestamp = 0.0
    if len(raw) < captured:
        raise PcapError("Truncated PCAPNG packet data")
    return _decode(index, timestamp, raw, original, PcapInfo(order, False, link_type, 0))


def _parse_ipv4(raw: bytes, offset: int) -> tuple[int, int, str, str] | None:
    if len(raw) < offset + 20 or raw[offset] >> 4 != 4:
        return None
    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20 or len(raw) < offset + ihl:
        return None
    protocol = raw[offset + 9]
    source = str(ipaddress.ip_address(raw[offset + 12 : offset + 16]))
    destination = str(ipaddress.ip_address(raw[offset + 16 : offset + 20]))
    return protocol, offset + ihl, source, destination


# IPv6 extension headers carry (next_header, hdr_ext_len) and are skipped to reach TCP/UDP.
_IPV6_EXT_HEADERS = {0, 43, 60}  # hop-by-hop, routing, destination options


def _parse_ipv6(raw: bytes, offset: int) -> tuple[int, int, str, str] | None:
    if len(raw) < offset + 40 or raw[offset] >> 4 != 6:
        return None
    source = str(ipaddress.ip_address(raw[offset + 8 : offset + 24]))
    destination = str(ipaddress.ip_address(raw[offset + 24 : offset + 40]))
    next_header = raw[offset + 6]
    pos = offset + 40
    for _ in range(8):  # ponytail: cap extension-header walk; covers common IoT captures
        if next_header in _IPV6_EXT_HEADERS and len(raw) >= pos + 2:
            next_header, ext_len = raw[pos], raw[pos + 1]
            pos += (ext_len + 1) * 8
        elif next_header == 44 and len(raw) >= pos + 8:  # fragment header, fixed 8 bytes
            next_header = raw[pos]
            pos += 8
        else:
            break
    return next_header, pos, source, destination


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
    if ether_type == 0x0800:
        parsed = _parse_ipv4(raw, offset)
    elif ether_type == 0x86DD:
        parsed = _parse_ipv6(raw, offset)
    else:
        return record
    if parsed is None:
        return record
    protocol, transport, record.source, record.destination = parsed
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
