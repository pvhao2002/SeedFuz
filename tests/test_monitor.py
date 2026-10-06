from __future__ import annotations

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from seedfuz.models import HealthSample
from seedfuz.monitor import DeviceMonitor, memory_leak_rate


def test_tcp_probe_detects_open_and_closed_ports() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        up = DeviceMonitor("127.0.0.1", timeout_seconds=1.0, tcp_port=port).sample()
        assert up.alive and "open" in up.detail
    finally:
        listener.close()
    # Port is closed now -> connection refused -> treated as down.
    down = DeviceMonitor("127.0.0.1", timeout_seconds=1.0, tcp_port=port).sample()
    assert not down.alive


@pytest.mark.parametrize("status, expected_alive", [(200, True), (404, True), (502, False)])
def test_http_probe_marks_5xx_as_down(status: int, expected_alive: bool) -> None:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(status)
            self.end_headers()

        def log_message(self, *args: object) -> None:  # silence test output
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_address[1]}/"
        sample = DeviceMonitor("127.0.0.1", timeout_seconds=2.0, http_url=url).sample()
        assert sample.alive is expected_alive
        assert str(status) in sample.detail
    finally:
        server.shutdown()
        thread.join(timeout=2)


def test_monitor_cli_runs_fixed_count(capsys: pytest.CaptureFixture[str]) -> None:
    from seedfuz.cli import main

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    try:
        code = main(
            ["monitor", "--host", "127.0.0.1", "--tcp-port", str(port), "--count", "1"]
        )
    finally:
        listener.close()
    assert code == 0
    assert "UP" in capsys.readouterr().out


def test_memory_leak_rate_detects_growth() -> None:
    samples = [HealthSample("t", True, memory_percent=float(v)) for v in (10, 20, 30)]
    assert memory_leak_rate(samples) == pytest.approx(10.0)
