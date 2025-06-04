# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
"""
Test for SyslogKafkaOutputMixin: ensure decoded messages are sent to Kafka backend.
"""
# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.syslog_kafka_output_mixin import (
    SyslogKafkaOutputMixin,
)


class DummyDecoder:
    def decode(self, message):
        class DummyModel:
            def model_dump_json(self, indent=None):
                return '{"msg": "decoded", "raw": "%s"}' % message

        return DummyModel()


class DummyKafkaBackend:
    def __init__(self):
        self.started = False
        self.sent = []

    async def start(self):
        self.started = True

    async def stop(self):
        self.started = False

    async def send(self, value, key=None, headers=None):
        self.sent.append((value, key, headers))


class TestSyslogKafkaOutputMixin(SyslogKafkaOutputMixin):
    pass


@pytest.mark.asyncio
async def test_process_syslog_messages_to_kafka_sends_decoded(monkeypatch):
    mixin = TestSyslogKafkaOutputMixin()
    backend = DummyKafkaBackend()
    decoder = DummyDecoder()
    messages = [b"test1", b"test2"]
    await mixin.process_syslog_messages_to_kafka(
        messages=messages,
        decoder=decoder,
        kafka_backend=backend,
        peer_info=None,
    )
    assert backend.started is True
    assert len(backend.sent) == 2
    assert backend.sent[0][0] == b'{"msg": "decoded", "raw": "test1"}'
    assert backend.sent[1][0] == b'{"msg": "decoded", "raw": "test2"}'
    await backend.stop()
    assert backend.started is False
