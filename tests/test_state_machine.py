from pathlib import Path

from seedfuz.pcap import read_pcap
from seedfuz.state_machine import infer_state_graph, session_token_ranges


def test_infers_ordered_application_transitions(sample_pcap: Path) -> None:
    graph = infer_state_graph(read_pcap(sample_pcap))
    assert graph.as_dict()["start"]["application-data"] == 1
    assert graph.as_dict()["application-data"]["application-data"] == 1
    assert graph.as_dict()["application-data"]["end"] == 1


def test_session_token_ranges_cover_cookie_and_param() -> None:
    payload = b"GET /x?token=abc123&q=1 HTTP/1.1\r\nCookie: sid=XYZ\r\n\r\n"
    ranges = session_token_ranges(payload)
    assert any(payload[s:e] == b"abc123" for s, e in ranges)
    assert any(payload[s:e] == b" sid=XYZ" for s, e in ranges)
