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

from unittest.mock import MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.framing import (
    FramingDetectionError,
    FramingMode,
)
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
        # Check that framing_helper is initialized
        assert hasattr(protocol, "framing_helper")
        # Check decoder setup
        assert protocol.decoder_type == "auto"
        assert isinstance(protocol.connection_cache, dict)
        assert isinstance(protocol.event_parsing_cache, dict)

    @pytest.mark.unit
    def test_buffer_property(self):
        """Test the buffer property compatibility."""
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        assert hasattr(protocol, "buffer"), "Protocol should have a buffer property"
        assert (
            protocol.buffer is protocol.framing_helper._buffer
        ), "Buffer property should reference framing_helper._buffer"

    @pytest.mark.unit
    def test_connection_made(self, caplog):
        """Test connection_made method."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()

        # Create a mock transport
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = ("192.168.1.1", 12345)

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport and peername are set
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)
        # Check log message
        assert "TCP connection established" in caplog.text

    @pytest.mark.unit
    def test_connection_made_unknown_peer(self, caplog):
        """Test connection_made method when peer info is not available."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()

        # Create a mock transport without peer info
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = None

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport is set and log message is created
        assert protocol.transport == mock_transport
        assert protocol.peername is None
        assert "TCP connection established" in caplog.text

    @pytest.mark.unit
    def test_get_buffer(self):
        """Test get_buffer method."""
        protocol = SyslogTCPProtocol()

        # Test with normal size
        buffer = protocol.get_buffer(1024)
        assert isinstance(buffer, bytearray)
        assert len(buffer) == 1024
        assert protocol._read_buffer is buffer

        # Test with size larger than max_buffer_size
        large_buffer = protocol.get_buffer(100000)
        assert isinstance(large_buffer, bytearray)
        assert len(large_buffer) == protocol.max_buffer_size
        assert protocol._read_buffer is large_buffer

    @pytest.mark.unit
    def test_buffer_updated_with_decoder(self, caplog):
        """Test buffer_updated method with decoder."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Patch the decoder's decode method
        with patch.object(protocol.decoder, "decode") as mock_decode:
            # Setup mock decoder response
            mock_decoded = MagicMock()
            mock_decoded.__class__.__name__ = "EventEnvelopeBaseModel"
            mock_decode.return_value = mock_decoded

            # Create test data with a complete message
            test_data = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
            protocol._read_buffer = bytearray(test_data)

            # Call buffer_updated
            protocol.buffer_updated(len(test_data))

            # Check that the decoder was called
            mock_decode.assert_called_once()
            # Check that the message was logged
            assert "Syslog message received" in caplog.text

    @pytest.mark.unit
    def test_buffer_updated_framing_error(self, caplog):
        """Test buffer_updated method with framing error."""
        caplog.set_level(logging.ERROR)
        protocol = SyslogTCPProtocol(framing_mode="transparent")
        protocol.peername = ("192.168.1.1", 12345)
        protocol.transport = MagicMock()

        # Create a method that raises FramingDetectionError when called
        def mock_add_data(data):
            raise FramingDetectionError("Test framing error")

        protocol.framing_helper.add_data = mock_add_data

        # Call buffer_updated with test data
        test_data = b"invalid data"
        protocol._read_buffer = bytearray(test_data)
        protocol.buffer_updated(len(test_data))

        # Check that the error was logged
        assert "Framing error" in caplog.text

        # Note: The "Closing connection due to framing error" message is logged at WARNING level
        # but we set the caplog level to ERROR, so we won't see it.
        # Instead, we'll just check that transport.close was called
        protocol.transport.close.assert_called_once()

    @pytest.mark.unit
    def test_eof_received(self, caplog):
        """Test eof_received method."""
        caplog.set_level(logging.DEBUG)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Add some data to the buffer
        protocol.framing_helper._buffer.extend(b"final message\n")

        # Mock extract_messages to return our test message
        original_extract = protocol.framing_helper.extract_messages
        protocol.framing_helper.extract_messages = lambda: [b"final message"]

        # Call eof_received
        result = protocol.eof_received()

        # Restore original method
        protocol.framing_helper.extract_messages = original_extract

        # Check that EOF was logged
        assert "EOF received" in caplog.text
        # Check return value (should be False to close the transport)
        assert result is False

    @pytest.mark.unit
    def test_eof_received_with_unparsed_data(self, caplog):
        """Test eof_received method with unparsed data."""
        caplog.set_level(logging.WARNING)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)

        # Add some data to the buffer that won't be extracted
        protocol.framing_helper._buffer.extend(b"incomplete message")

        # Mock extract_messages to return empty list (no messages extracted)
        original_extract = protocol.framing_helper.extract_messages
        protocol.framing_helper.extract_messages = lambda: []

        # Call eof_received
        protocol.eof_received()

        # Restore original method
        protocol.framing_helper.extract_messages = original_extract

        # Check that warning about unparsed data was logged
        assert "Discarding" in caplog.text

    @pytest.mark.unit
    def test_connection_lost_with_exception(self, caplog):
        """Test connection_lost method with an exception."""
        caplog.set_level(logging.WARNING)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)
        protocol.transport = MagicMock()

        # Call connection_lost with a test exception
        test_exception = Exception("Connection error")
        protocol.connection_lost(test_exception)

        # Check that the warning is properly logged
        assert "TCP connection closed with error" in caplog.text
        # Check that resources are cleaned up
        assert protocol._read_buffer is None
        assert protocol.transport is None

    @pytest.mark.unit
    def test_connection_lost_without_exception(self, caplog):
        """Test connection_lost method without an exception."""
        caplog.set_level(logging.INFO)
        protocol = SyslogTCPProtocol()
        protocol.peername = ("192.168.1.1", 12345)
        protocol.transport = MagicMock()

        # Call connection_lost without an exception
        protocol.connection_lost(None)

        # Check that the info is properly logged
        assert "TCP connection closed" in caplog.text
        # Check that resources are cleaned up
        assert protocol._read_buffer is None
        assert protocol.transport is None

    @pytest.mark.unit
    def test_tcp_with_different_framing_modes(self):
        """Test TCP protocol with different framing modes."""
        # Test with non_transparent mode
        protocol_non_transparent = SyslogTCPProtocol(framing_mode="non_transparent")
        assert (
            protocol_non_transparent.framing_helper.framing_mode
            == FramingMode.NON_TRANSPARENT
        )

        # Test with transparent mode
        protocol_transparent = SyslogTCPProtocol(framing_mode="transparent")
        assert (
            protocol_transparent.framing_helper.framing_mode == FramingMode.TRANSPARENT
        )

        # Test with auto mode (default)
        protocol_auto = SyslogTCPProtocol()
        assert protocol_auto.framing_helper.framing_mode == FramingMode.AUTO

    @pytest.mark.unit
    def test_tcp_buffer_overflow_handling(self, caplog):
        """Test TCP protocol handling of buffer overflow."""
        caplog.set_level(logging.DEBUG)
        protocol = SyslogTCPProtocol(max_message_length=100)
        protocol.peername = ("192.168.1.1", 12345)

        # Create a large message that exceeds max_message_length
        large_message = b"X" * 200
        protocol._read_buffer = bytearray(large_message)

        # Call buffer_updated
        protocol.buffer_updated(len(large_message))

        # Check debug log for buffer size
        assert "Received TCP data" in caplog.text
        # Check that the entries in the structured log contain the correct values
        for record in caplog.records:
            if "Received TCP data" in record.message:
                assert record.nbytes == 200
                assert record.host == "192.168.1.1"
                assert record.port == 12345
                break
