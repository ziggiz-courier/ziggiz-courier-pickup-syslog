# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
"""
Test for KafkaOutputBackend (aiokafka-based output backend).
"""


# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.kafka_output_backend import KafkaOutputBackend


@pytest.mark.asyncio
async def test_kafka_output_backend_send(monkeypatch):

    class DummyProducer:
        def __init__(self, *a, **kw):
            self.started = False
            self.sent = []

        async def start(self):
            self.started = True

        async def stop(self):
            self.started = False

        async def send_and_wait(self, topic, value, key=None, headers=None):
            self.sent.append((topic, value, key, headers))
            return True

    # Patch AIOKafkaProducer to DummyProducer
    monkeypatch.setattr(
        "ziggiz_courier_pickup_syslog.kafka_output_backend.AIOKafkaProducer",
        DummyProducer,
    )
    backend = KafkaOutputBackend(bootstrap_servers="localhost:9092", topic="test-topic")
    await backend.start()
    await backend.send(b"test-value", key=b"test-key")
    assert backend.producer.started is True  # type: ignore[attr-defined]
    assert backend.producer.sent == [("test-topic", b"test-value", b"test-key", None)]  # type: ignore[attr-defined]
    await backend.stop()
    assert backend.producer.started is False  # type: ignore[attr-defined]
