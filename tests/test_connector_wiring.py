from __future__ import annotations

import pytest

from ai_cyber_os.hydra import (
    CheckpointStore,
    ConnectorAction,
    ConnectorConfig,
    ConnectorFamily,
    ConnectorPoller,
    InMemoryCheckpointStore,
    SimulatedConnector,
    SimulatedEvent,
)


def _connector() -> SimulatedConnector:
    config = ConnectorConfig(
        connector_id="test-connector",
        tenant_id="tenant-a",
        name="Test Connector",
        family=ConnectorFamily.SIEM,
        enabled=True,
    )
    return SimulatedConnector(
        config,
        events=[
            SimulatedEvent(
                event_type="security.event",
                payload={"severity": "high"},
            )
        ],
    )


def test_checkpoint_store_contract_is_not_silent():
    class PartialStore(CheckpointStore):
        def get(self, connector_id: str):
            return None

        def put(self, checkpoint):
            return None

    with pytest.raises(TypeError):
        PartialStore()


def test_connector_poller_compatibility_path_is_wired():
    connector = _connector()
    connector.initialize()
    store = InMemoryCheckpointStore()
    poller = ConnectorPoller(connector, store)

    result = poller.poll()

    assert result.success is True
    assert len(result.events) == 1
    checkpoint = store.get(connector.connector_id)
    assert checkpoint is not None
    assert checkpoint.tenant_id == "tenant-a"
    assert checkpoint.cursor == result.cursor


def test_connector_poller_once_uses_same_checkpoint_contract():
    connector = _connector()
    connector.initialize()
    store = InMemoryCheckpointStore()
    poller = ConnectorPoller(connector, store)

    result = poller.poll_once()

    assert result.success is True
    checkpoint = store.get(connector.connector_id)
    assert checkpoint is not None
    assert checkpoint.cursor == result.cursor
