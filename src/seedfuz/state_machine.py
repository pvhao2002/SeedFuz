"""Small protocol state graph inferred from captured TCP/UDP traffic."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field

from .models import PacketRecord


@dataclass(slots=True)
class StateGraph:
    transitions: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))

    def add(self, source: str, destination: str) -> None:
        self.transitions[source][destination] += 1

    def next_states(self, state: str) -> list[str]:
        return [name for name, _ in self.transitions.get(state, Counter()).most_common()]

    def as_dict(self) -> dict[str, dict[str, int]]:
        return {source: dict(destinations) for source, destinations in self.transitions.items()}


def packet_state(packet: PacketRecord) -> str:
    if packet.protocol == "udp":
        return "datagram"
    if packet.protocol != "tcp" or packet.tcp_flags is None:
        return "data" if packet.payload else "idle"
    flags = packet.tcp_flags
    if flags & 0x04:
        return "reset"
    if flags & 0x01:
        return "closing"
    if flags & 0x02 and not flags & 0x10:
        return "syn-sent"
    if flags & 0x02 and flags & 0x10:
        return "syn-ack"
    if packet.payload:
        return "application-data"
    if flags & 0x10:
        return "established"
    return "tcp-other"


# Header/parameter names whose values are session credentials to keep fixed while fuzzing.
_SESSION_HEADERS = (b"cookie:", b"set-cookie:", b"authorization:")
_SESSION_PARAMS = (b"token", b"session", b"sessionid", b"sid", b"csrf", b"csrftoken", b"auth")


def session_token_ranges(payload: bytes) -> list[tuple[int, int]]:
    """Find byte ranges of session cookies/tokens so mutation can leave them intact.

    Covers HTTP ``Cookie``/``Authorization`` header values and ``token=``/``session=``
    style parameters. Returns ``(start, end)`` half-open ranges over ``payload``.
    """
    ranges: list[tuple[int, int]] = []
    lowered = payload.lower()
    for header in _SESSION_HEADERS:  # value = after the colon up to end of the header line
        start = 0
        while (found := lowered.find(header, start)) != -1:
            value_start = found + len(header)
            line_end = payload.find(b"\r\n", value_start)
            end = len(payload) if line_end == -1 else line_end
            ranges.append((value_start, end))
            start = end
    for param in _SESSION_PARAMS:  # value = after name= up to the next delimiter
        start = 0
        while (found := lowered.find(param + b"=", start)) != -1:
            after = found + len(param) + 1
            if found > 0 and lowered[found - 1] not in b"?&; \t\r\n=":
                start = after  # part of a longer word, skip
                continue
            end = after
            while end < len(payload) and payload[end] not in b"&; \r\n":
                end += 1
            ranges.append((after, end))
            start = end
    return _merge_ranges(ranges)


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    cleaned = sorted((s, e) for s, e in ranges if e > s)
    merged: list[tuple[int, int]] = []
    for start, end in cleaned:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def infer_state_graph(packets: Iterable[PacketRecord]) -> StateGraph:
    graph = StateGraph()
    previous = "start"
    for packet in packets:
        current = packet_state(packet)
        graph.add(previous, current)
        previous = current
    graph.add(previous, "end")
    return graph
