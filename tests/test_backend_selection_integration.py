# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
"""
Integration test: configuration-driven backend selection and message dispatch.
"""
# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.config import Config
from ziggiz_courier_pickup_syslog.server import SyslogServer


class DummyKafkaBackend:
    def __init__(self, *args, **kwargs):
        self.started = False
        self.sent = []

    async def start(self):
        self.started = True

    async def stop(self):
        self.started = False

    async def send(self, value, key=None, headers=None):
        self.sent.append((value, key, headers))


class DummyDecoder:
    def decode(self, message):
        class DummyModel:
            def model_dump_json(self, indent=None):
                return '{"msg": "decoded", "raw": "%s"}' % message

        return DummyModel()


class DummyProtocol:
    def __init__(self, server, decoder):
        self.server = server
        self.decoder = decoder
        self.peername = ("127.0.0.1", 12345)

    async def handle(self, messages):
        # Simulate backend selection and message processing
        if self.server.output_backend:
            # Kafka backend
            await self.server.output_backend.start()
            for msg in messages:
                decoded = self.decoder.decode(msg.decode("utf-8"))
                value = decoded.model_dump_json().encode("utf-8")
                await self.server.output_backend.send(value=value)
        else:
            # Console backend (simulate log call)
            self.console_log = []
            for msg in messages:
                decoded = self.decoder.decode(msg.decode("utf-8"))
                self.console_log.append(decoded.model_dump_json())


@pytest.mark.asyncio
async def test_backend_selection_and_dispatch(monkeypatch):
    # Patch KafkaOutputBackend to DummyKafkaBackend
    monkeypatch.setattr(
        "ziggiz_courier_pickup_syslog.kafka_output_backend.KafkaOutputBackend",
        DummyKafkaBackend,
    )
    # Use a valid RFC5424 syslog message
    VALID_SYSLOG_MSG = (
        b"<165>1 2025-06-02T12:34:56.000Z myhost ziggiz-courier 12345 PICKUP42 "
        b'[exampleSDID@32473 iut="3"][ziggiz@32473 event="pickup" trackingId="PKG12345"] '
        b"Courier package pickup notification"
    )
    # Kafka config
    config = Config(
        output_backend="kafka", kafka_bootstrap_servers="dummy", kafka_topic="dummy"
    )
    server = SyslogServer(config)
    proto = DummyProtocol(server, DummyDecoder())
    await proto.handle([VALID_SYSLOG_MSG])
    assert isinstance(server.output_backend, DummyKafkaBackend)
    assert (
        server.output_backend.sent[0][0]
        == b'{"msg": "decoded", "raw": "<165>1 2025-06-02T12:34:56.000Z myhost ziggiz-courier 12345 PICKUP42 [exampleSDID@32473 iut="3"][ziggiz@32473 event="pickup" trackingId="PKG12345"] Courier package pickup notification"}'
    )
    # Console config
    config2 = Config(output_backend="console")
    server2 = SyslogServer(config2)
    proto2 = DummyProtocol(server2, DummyDecoder())
    await proto2.handle([VALID_SYSLOG_MSG])
    assert not hasattr(server2, "output_backend") or server2.output_backend is None
    assert (
        proto2.console_log[0]
        == '{"msg": "decoded", "raw": "<165>1 2025-06-02T12:34:56.000Z myhost ziggiz-courier 12345 PICKUP42 [exampleSDID@32473 iut="3"][ziggiz@32473 event="pickup" trackingId="PKG12345"] Courier package pickup notification"}'
    )
