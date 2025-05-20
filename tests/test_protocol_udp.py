# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the UDP protocol implementation

# Standard library imports
import logging

from unittest.mock import MagicMock

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol


class TestSyslogUDPProtocol:
    """Tests for the SyslogUDPProtocol class."""

    def test_init(self):
        """Test initialization of the protocol."""
        protocol = SyslogUDPProtocol()

        # Check that the logger is properly initialized
        assert protocol.logger.name == "ziggiz_courier_pickup_syslog.protocol.udp"
        assert protocol.transport is None

    def test_connection_made(self, caplog):
        """Test connection_made method."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Create a mock transport
        mock_transport = MagicMock()
        mock_socket = MagicMock()
        mock_socket.getsockname.return_value = ("127.0.0.1", 514)
        mock_transport.get_extra_info.return_value = mock_socket

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport is set and log message is created
        assert protocol.transport == mock_transport
        assert "UDP server started on 127.0.0.1:514" in caplog.text

    def test_connection_made_no_socket_info(self, caplog):
        """Test connection_made method when socket info is not available."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Create a mock transport without socket info
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = None

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport is set and log message is created
        assert protocol.transport == mock_transport
        assert "UDP server started" in caplog.text

    def test_datagram_received(self, caplog):
        """Test datagram_received method."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Call datagram_received with test data
        data = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        addr = ("192.168.1.1", 54321)
        protocol.datagram_received(data, addr)

        # Check that the message is properly logged
        assert "192.168.1.1:54321" in caplog.text
        assert "su root" in caplog.text

    def test_error_received(self, caplog):
        """Test error_received method."""
        caplog.set_level(logging.ERROR)
        protocol = SyslogUDPProtocol()

        # Call error_received with a test exception
        test_exception = OSError("Test error")
        protocol.error_received(test_exception)

        # Check that the error is properly logged
        assert "Error in UDP server: Test error" in caplog.text

    def test_connection_lost_with_exception(self, caplog):
        """Test connection_lost method with an exception."""
        caplog.set_level(logging.WARNING)
        protocol = SyslogUDPProtocol()

        # Call connection_lost with a test exception
        test_exception = Exception("Connection error")
        protocol.connection_lost(test_exception)

        # Check that the warning is properly logged
        assert (
            "UDP server connection closed with error: Connection error" in caplog.text
        )

    def test_connection_lost_without_exception(self, caplog):
        """Test connection_lost method without an exception."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Call connection_lost without an exception
        protocol.connection_lost(None)

        # Check that the info is properly logged
        assert "UDP server connection closed" in caplog.text
