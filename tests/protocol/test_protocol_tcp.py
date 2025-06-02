# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the TCP protocol implementation

# NOTE: THESE TESTS ARE OUTDATED
# The base protocol implementation has been refactored and no longer uses framing_helper.
# Base functionality is now tested in test_base_stream_protocol.py and test_base_stream_extended.py.
#
# The following tests are now obsolete as they're covered by base class tests:
# - test_get_buffer
# - test_eof_received (basic functionality)
# - test_connection_lost_without_exception
# - test_buffer_updated (basic functionality)
#
# This file should be updated to only test TCP-specific functionality like
# IP filtering and TCP-specific connection handling.

# NOTE: Some tests in this file are now redundant with tests in test_base_stream_protocol.py
# and test_base_stream_extended.py, which test the base functionality used by all stream protocols.
# Specifically, the following tests are obsolete and could be removed:
#   - test_get_buffer
#   - test_eof_received (basic functionality)
#   - test_connection_lost_without_exception
#
# This file should focus on TCP-specific functionality like IP filtering and TCP-specific connection handling.

# Standard library imports
import logging

from unittest.mock import MagicMock

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol


class TestSyslogTCPProtocol:
    """Tests for the SyslogTCPProtocol class."""

    @pytest.mark.unit
    def test_init(self):
        """Test initialization of the protocol."""
        protocol = SyslogTCPProtocol()

        # Check that the logger is properly initialized
        assert protocol.logger.name == "ziggiz_courier_pickup_syslog.protocol.tcp"
        assert protocol.transport is None
        assert protocol.peername is None
        assert protocol._read_buffer is None
        assert protocol.max_buffer_size == 65536
        # Check decoder setup
        assert protocol.decoder_type == "auto"
        assert isinstance(protocol.connection_cache, dict)
        assert isinstance(protocol.event_parsing_cache, dict)

    @pytest.mark.unit
    def test_connection_made(self, caplog):
        """Test connection_made method."""
        caplog.set_level(logging.DEBUG)
        protocol = SyslogTCPProtocol()

        # Create a mock transport
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = ("192.168.1.1", 12345)

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport and peername are set
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)
        # Functional: verify state
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)

    @pytest.mark.unit
    def test_connection_made_unknown_peer(self, caplog):
        """Test connection_made method when peer info is not available."""
        caplog.set_level(logging.DEBUG)
        protocol = SyslogTCPProtocol()

        # Create a mock transport without peer info
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = None

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Functional: verify state
        assert protocol.transport == mock_transport
        assert protocol.peername is None
