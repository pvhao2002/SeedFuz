from __future__ import annotations

import struct
from pathlib import Path

import pytest


def ethernet_ipv4_tcp(payload: bytes, flags: int = 0x18) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    total_length = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        6,
        0,
        b"\xc0\xa8\x01\x02",
        b"\xc0\xa8\x01\x32",
    )
    tcp = struct.pack("!HHIIBBHHH", 50000, 80, 1, 1, 0x50, flags, 8192, 0, 0)
    return ethernet + ipv4 + tcp + payload


def ethernet_ipv6_tcp(payload: bytes, flags: int = 0x18) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x86\xdd"
    tcp = struct.pack("!HHIIBBHHH", 50000, 80, 1, 1, 0x50, flags, 8192, 0, 0)
    body = tcp + payload
    source = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"
    dest = b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x02"
    ipv6 = struct.pack("!IHBB", 0x60000000, len(body), 6, 64) + source + dest
    return ethernet + ipv6 + body


def _raw_pcap(path: Path, frames: list[bytes]) -> Path:
    with path.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1")
        stream.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            stream.write(struct.pack("<IIII", 1_700_000_000 + index, 0, len(frame), len(frame)))
            stream.write(frame)
    return path


def _pcapng_block(block_type: int, body: bytes) -> bytes:
    total = 12 + len(body)
    return struct.pack("<II", block_type, total) + body + struct.pack("<I", total)


def write_pcapng(path: Path, payloads: list[bytes]) -> Path:
    shb = _pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    idb = _pcapng_block(0x00000001, struct.pack("<HHI", 1, 0, 65535))
    blocks = [shb, idb]
    for index, payload in enumerate(payloads):
        frame = ethernet_ipv4_tcp(payload)
        padded = frame + b"\x00" * (-len(frame) % 4)
        epb_body = struct.pack("<IIIII", 0, 0, index, len(frame), len(frame)) + padded
        blocks.append(_pcapng_block(0x00000006, epb_body))
    path.write_bytes(b"".join(blocks))
    return path


def write_pcap(path: Path, payloads: list[bytes]) -> Path:
    with path.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1")
        stream.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for index, payload in enumerate(payloads):
            packet = ethernet_ipv4_tcp(payload)
            stream.write(
                struct.pack("<IIII", 1_700_000_000 + index, index * 1000, len(packet), len(packet))
            )
            stream.write(packet)
    return path


@pytest.fixture
def sample_pcap(tmp_path: Path) -> Path:
    return write_pcap(tmp_path / "sample.pcap", [b"GET / HTTP/1.0\r\n\r\n", b"USER admin\r\n"])


@pytest.fixture
def sample_pcapng(tmp_path: Path) -> Path:
    return write_pcapng(tmp_path / "sample.pcapng", [b"GET / HTTP/1.0\r\n\r\n", b"USER admin\r\n"])


@pytest.fixture
def ipv6_pcap(tmp_path: Path) -> Path:
    return _raw_pcap(tmp_path / "ipv6.pcap", [ethernet_ipv6_tcp(b"POST /login HTTP/1.1\r\n\r\n")])
