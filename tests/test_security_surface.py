from __future__ import annotations

import socket

from ai_cyber_os.hydra import run_hydra_phase


def test_default_runtime_does_not_open_network_connections(monkeypatch):
    def blocked(*_args, **_kwargs):
        raise AssertionError("default HYDRA runtime attempted live network access")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)

    result = run_hydra_phase("all")
    assert result["summary"]["success"] is True, result
