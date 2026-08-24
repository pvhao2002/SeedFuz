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
