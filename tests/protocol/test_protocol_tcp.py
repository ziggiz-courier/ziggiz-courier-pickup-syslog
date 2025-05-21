# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the TCP protocol implementation

# Standard library imports


# Third-party imports

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol


class TestSyslogTCPProtocol:
    """Tests for the SyslogTCPProtocol class."""

    def test_init(self):
        """Test initialization of the protocol."""
        protocol = SyslogTCPProtocol()

        # Check that the logger is properly initialized
        assert protocol.logger.name == "ziggiz_courier_pickup_syslog.protocol.tcp"
        assert protocol.transport is None
        assert protocol.peername is None
        assert protocol._read_buffer is None
        assert protocol.max_buffer_size == 65536
        # Check that framing_helper is initialized
        assert hasattr(protocol, "framing_helper")
        # Check decoder setup
        assert protocol.decoder_type == "auto"
        assert isinstance(protocol.connection_cache, dict)
        assert isinstance(protocol.event_parsing_cache, dict)

    def test_buffer_property(self):
        """Test the buffer property compatibility."""
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        assert hasattr(protocol, "buffer"), "Protocol should have a buffer property"
        assert (
            protocol.buffer is protocol.framing_helper._buffer
        ), "Buffer property should reference framing_helper._buffer"
