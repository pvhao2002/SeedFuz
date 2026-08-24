from pathlib import Path

from seedfuz.pcap import read_pcap
from seedfuz.state_machine import infer_state_graph


def test_infers_ordered_application_transitions(sample_pcap: Path) -> None:
    graph = infer_state_graph(read_pcap(sample_pcap))
    assert graph.as_dict()["start"]["application-data"] == 1
    assert graph.as_dict()["application-data"]["application-data"] == 1
    assert graph.as_dict()["application-data"]["end"] == 1
