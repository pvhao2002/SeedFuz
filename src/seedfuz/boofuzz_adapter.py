"""Optional Boofuzz session builder for protocol-specific extension work."""

from __future__ import annotations

from pathlib import Path
from typing import Any


def build_boofuzz_session(
    host: str,
    port: int,
    protocol: str,
    seeds: list[bytes],
    results_db: str | Path,
    web_port: int = 26000,
) -> Any:
    """Build (but do not start) a Boofuzz graph from ordered captured messages.

    Keeping construction separate from ``fuzz()`` makes explicit authorization and
    operator review possible before network traffic begins.
    """
    try:
        from boofuzz import (
            Bytes,
            Request,
            Session,
            Target,
            TCPSocketConnection,
            UDPSocketConnection,
        )
    except ImportError as exc:
        raise RuntimeError("Install project dependencies to enable Boofuzz") from exc
    connection_cls = TCPSocketConnection if protocol == "tcp" else UDPSocketConnection
    target = Target(connection=connection_cls(host, port))
    session = Session(
        target=target,
        db_filename=str(results_db),
        web_port=web_port,
        keep_web_open=False,
        receive_data_after_fuzz=True,
    )
    previous = None
    for index, seed in enumerate(seeds):
        request = Request(
            f"captured-message-{index}", children=(Bytes(seed, name=f"payload-{index}"),)
        )
        session.connect(request) if previous is None else session.connect(previous, request)
        previous = request
    return session
