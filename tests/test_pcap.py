from __future__ import annotations

from pathlib import Path

import pytest

from seedfuz.pcap import PcapError, detect_sensitive_fields, read_pcap, usable_seeds


def test_reads_tcp_payloads(sample_pcap: Path) -> None:
    packets = read_pcap(sample_pcap)
    assert len(packets) == 2
    assert packets[0].protocol == "tcp"
    assert packets[0].source == "192.168.1.2"
    assert packets[0].destination_port == 80
    assert usable_seeds(packets) == [b"GET / HTTP/1.0\r\n\r\n", b"USER admin\r\n"]


def test_rejects_non_pcap(tmp_path: Path) -> None:
    invalid = tmp_path / "bad.pcap"
    invalid.write_bytes(b"not a capture")
    with pytest.raises(PcapError, match="classic PCAP"):
        read_pcap(invalid)


def test_sensitive_field_detection_prioritizes_header_and_delimiter() -> None:
    fields = detect_sensitive_fields(b"\x08name=admin")
    assert any(field.offset == 0 and "header" in field.reasons for field in fields)
    assert any(field.offset == 5 and "delimiter" in field.reasons for field in fields)
