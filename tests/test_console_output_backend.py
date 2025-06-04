# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
"""
Test for console (logging) output backend via SyslogMessageProcessingMixin.
"""
# Standard library imports

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.syslog_message_processing_mixin import (
    SyslogMessageProcessingMixin,
)


class DummyLogger:
    def __init__(self):
        self.infos = []
        self.debugs = []
        self.warnings = []

    def info(self, msg, extra=None):
        self.infos.append((msg, extra))

    def debug(self, msg, extra=None):
        self.debugs.append((msg, extra))

    def warning(self, msg, extra=None):
        self.warnings.append((msg, extra))


class DummyDecoder:
    def decode(self, message):
        class DummyModel:
            def model_dump_json(self, indent=None):
                return '{"msg": "decoded", "raw": "%s"}' % message

        return DummyModel()


class DummyTracer:
    class DummySpan:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            return False

    def start_as_current_span(self, *a, **kw):
        return self.DummySpan()


def dummy_span_attributes(peer_info, msg):
    return {"peer": peer_info}


class DummyPeer:
    pass


class TestSyslogMessageProcessingMixin(SyslogMessageProcessingMixin):
    peername = ("127.0.0.1", 12345)
    _test_force_log = True


@pytest.mark.parametrize("enable_model_json_output", [True, False])
def test_process_syslog_messages_console(enable_model_json_output):
    mixin = TestSyslogMessageProcessingMixin()
    logger = DummyLogger()
    decoder = DummyDecoder()
    tracer = DummyTracer()
    messages = [b"test1"]
    mixin.process_syslog_messages(
        messages=messages,
        logger=logger,
        decoder=decoder,
        tracer=tracer,
        span_name="test-span",
        span_attributes_func=dummy_span_attributes,
        enable_model_json_output=enable_model_json_output,
        peer_info={"host": "127.0.0.1", "port": 12345},
    )
    # Should always log info
    assert any("Syslog message received" in msg for msg, _ in logger.infos)
    # Should log debug with JSON if enabled
    if enable_model_json_output:
        assert any(
            "Decoded model JSON representation:" in msg for msg, _ in logger.debugs
        )
    else:
        assert not any(
            "Decoded model JSON representation:" in msg for msg, _ in logger.debugs
        )
