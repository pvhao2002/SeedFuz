"""Generate a deterministic classic PCAP for local dry-run demonstrations."""

from __future__ import annotations

import struct
from pathlib import Path


def packet(payload: bytes, sequence: int) -> bytes:
    ethernet = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00"
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(payload),
        sequence,
        0,
        64,
        6,
        0,
        b"\xc0\xa8\x01\x02",
        b"\xc0\xa8\x01\x32",
    )
    tcp = struct.pack("!HHIIBBHHH", 50000, 8080, sequence, 1, 0x50, 0x18, 8192, 0, 0)
    return ethernet + ipv4 + tcp + payload


def main() -> None:
    destination = Path(__file__).parents[1] / "datasets" / "sample_http.pcap"
    payloads = [b"GET /status HTTP/1.0\r\nHost: iot.local\r\n\r\n", b"SET name=device&id=1\r\n"]
    with destination.open("wb") as stream:
        stream.write(b"\xd4\xc3\xb2\xa1")
        stream.write(struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1))
        for index, payload in enumerate(payloads, 1):
            raw = packet(payload, index)
            stream.write(
                struct.pack("<IIII", 1_700_000_000 + index, index * 1000, len(raw), len(raw))
            )
            stream.write(raw)
    print(destination)


if __name__ == "__main__":
    main()
