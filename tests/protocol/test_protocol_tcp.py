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
import logging

from unittest.mock import MagicMock

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
        assert protocol.buffer == bytearray()
        assert protocol._read_buffer is None
        assert protocol.max_buffer_size == 65536

    def test_connection_made(self, caplog):
        """Test connection_made method."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()

        # Create a mock transport
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = ("127.0.0.1", 54321)

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport and peer info are set and log message is created
        assert protocol.transport == mock_transport
        assert protocol.peername == ("127.0.0.1", 54321)
        assert "TCP connection established from 127.0.0.1:54321" in caplog.text

    def test_connection_made_no_peer_info(self, caplog):
        """Test connection_made method when peer info is not available."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()

        # Create a mock transport without peer info
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = None

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport is set and log message is created with default peer info
        assert protocol.transport == mock_transport
        assert "TCP connection established from unknown:unknown" in caplog.text

    def test_get_buffer(self):
        """Test get_buffer method."""
        protocol = SyslogTCPProtocol()

        # Test with size hint less than max buffer size
        buffer = protocol.get_buffer(1024)
        assert len(buffer) == 1024
        assert protocol._read_buffer is buffer

        # Test with size hint greater than max buffer size
        buffer = protocol.get_buffer(100000)
        assert len(buffer) == 65536  # Should be capped at max_buffer_size
        assert protocol._read_buffer is buffer

    def test_buffer_updated_single_message(self, caplog):
        """Test buffer_updated method with a single complete message."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Create a buffer with a complete message
        test_message = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
        protocol._read_buffer = bytearray(test_message)

        # Call buffer_updated
        protocol.buffer_updated(len(test_message))

        # Check that the message is properly processed and logged
        assert (
            len(protocol.buffer) == 0
        )  # The buffer should be empty as the message was complete
        assert "192.168.1.1:12345" in caplog.text
        assert "su root" in caplog.text

    def test_buffer_updated_multiple_messages(self, caplog):
        """Test buffer_updated method with multiple messages."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Create a buffer with multiple complete messages
        test_message = (
            b"<34>Oct 11 22:14:15 host1 app1: message 1\n"
            b"<35>Oct 11 22:14:16 host2 app2: message 2\n"
            b"<36>Oct 11 22:14:17 host3 app3: message 3\n"
        )
        protocol._read_buffer = bytearray(test_message)

        # Call buffer_updated
        protocol.buffer_updated(len(test_message))

        # Check that all messages are properly processed and logged
        assert (
            len(protocol.buffer) == 0
        )  # The buffer should be empty as all messages were complete
        assert "message 1" in caplog.text
        assert "message 2" in caplog.text
        assert "message 3" in caplog.text

    def test_buffer_updated_partial_message(self, caplog):
        """Test buffer_updated method with a partial message."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Create a buffer with a partial message
        test_message = b"<34>Oct 11 22:14:15 mymachine su: 'su root"
        protocol._read_buffer = bytearray(test_message)

        # Call buffer_updated
        protocol.buffer_updated(len(test_message))

        # Check that the message is stored in the buffer but not logged yet
        assert bytes(protocol.buffer) == test_message
        assert "su root" not in caplog.text

        # Now add the rest of the message
        rest_of_message = b"' failed for lonvick on /dev/pts/8\n"
        protocol._read_buffer = bytearray(rest_of_message)
        protocol.buffer_updated(len(rest_of_message))

        # Check that the complete message is now processed and logged
        assert len(protocol.buffer) == 0
        assert "su root" in caplog.text

    def test_buffer_updated_message_with_remainder(self, caplog):
        """Test buffer_updated method with a complete message and partial next message."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Create a buffer with one complete message and part of another
        test_message = (
            b"<34>Oct 11 22:14:15 host1 app1: message 1\n"
            b"<35>Oct 11 22:14:16 host2 app2: partial"
        )
        protocol._read_buffer = bytearray(test_message)

        # Call buffer_updated
        protocol.buffer_updated(len(test_message))

        # Check that the first message is processed and the second is still in buffer
        assert bytes(protocol.buffer) == b"<35>Oct 11 22:14:16 host2 app2: partial"
        assert "message 1" in caplog.text
        assert "partial" not in caplog.text

    def test_eof_received_with_data(self, caplog):
        """Test eof_received method when there's data in the buffer."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Add some data to the buffer
        protocol.buffer = bytearray(b"<34>Oct 11 22:14:15 mymachine su: final message")

        # Call eof_received
        result = protocol.eof_received()

        # Check that the message is processed and the buffer is cleared
        assert not result  # Should return False to close the transport
        assert "Final syslog message" in caplog.text
        assert "final message" in caplog.text
        assert len(protocol.buffer) == 0

    def test_eof_received_without_data(self, caplog):
        """Test eof_received method when the buffer is empty."""
        caplog.set_level(logging.DEBUG)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Call eof_received
        result = protocol.eof_received()

        # Check that no message is processed and the function returns False
        assert not result  # Should return False to close the transport
        assert "EOF received from 192.168.1.1:12345" in caplog.text
        assert "Final syslog message" not in caplog.text

    def test_connection_lost_with_exception(self, caplog):
        """Test connection_lost method with an exception."""
        caplog.set_level(logging.WARNING)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)
        protocol.buffer = bytearray(b"some data")
        protocol._read_buffer = bytearray(b"some buffer")

        # Call connection_lost with a test exception
        test_exception = Exception("Connection error")
        protocol.connection_lost(test_exception)

        # Check that the warning is properly logged and buffers are cleared
        assert (
            "TCP connection from 192.168.1.1:12345 closed with error: Connection error"
            in caplog.text
        )
        assert len(protocol.buffer) == 0
        assert protocol._read_buffer is None

    def test_connection_lost_without_exception(self, caplog):
        """Test connection_lost method without an exception."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)
        protocol.buffer = bytearray(b"some data")
        protocol._read_buffer = bytearray(b"some buffer")

        # Call connection_lost without an exception
        protocol.connection_lost(None)

        # Check that the info is properly logged and buffers are cleared
        assert "TCP connection from 192.168.1.1:12345 closed" in caplog.text
        assert len(protocol.buffer) == 0
        assert protocol._read_buffer is None
