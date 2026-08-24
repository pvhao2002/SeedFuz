"""Safe dry-run, TCP, and UDP packet transports."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Protocol


@dataclass(slots=True)
class SendResult:
    bytes_sent: int
    response: bytes = b""


class Transport(Protocol):
    def send(self, data: bytes) -> SendResult: ...


class DryRunTransport:
    """Record successful sends without touching the network."""

    def send(self, data: bytes) -> SendResult:
        return SendResult(len(data), b"DRY-RUN")


class SocketTransport:
    def __init__(self, host: str, port: int, protocol: str, timeout: float = 1.0) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol
        self.timeout = timeout

    def send(self, data: bytes) -> SendResult:
        socket_type = socket.SOCK_STREAM if self.protocol == "tcp" else socket.SOCK_DGRAM
        with socket.socket(socket.AF_INET, socket_type) as client:
            client.settimeout(self.timeout)
            if socket_type == socket.SOCK_STREAM:
                client.connect((self.host, self.port))
                client.sendall(data)
                try:
                    response = client.recv(65535)
                except TimeoutError:
                    response = b""
                return SendResult(len(data), response)
            sent = client.sendto(data, (self.host, self.port))
            try:
                response, _ = client.recvfrom(65535)
            except TimeoutError:
                response = b""
            return SendResult(sent, response)
