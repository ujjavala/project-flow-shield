"""Regression tests for Temporal history-safe worker registration."""

from unittest.mock import AsyncMock, patch

import pytest

from app.temporal import client as temporal_client_module
from app.temporal.workflows.ping import PingWorkflow


@pytest.mark.asyncio
async def test_general_worker_registers_only_history_safe_ping_workflow():
    temporal_client = object()
    worker_instance = object()

    with (
        patch.object(
            temporal_client_module,
            "get_temporal_client",
            AsyncMock(return_value=temporal_client),
        ),
        patch.object(temporal_client_module, "Worker", return_value=worker_instance) as worker,
    ):
        result = await temporal_client_module.create_worker()

    assert result is worker_instance
    worker.assert_called_once_with(
        temporal_client,
        task_queue=temporal_client_module.settings.TEMPORAL_TASK_QUEUE,
        workflows=[PingWorkflow],
        activities=[],
    )
