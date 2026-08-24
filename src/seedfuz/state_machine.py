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


def infer_state_graph(packets: Iterable[PacketRecord]) -> StateGraph:
    graph = StateGraph()
    previous = "start"
    for packet in packets:
        current = packet_state(packet)
        graph.add(previous, current)
        previous = current
    graph.add(previous, "end")
    return graph
