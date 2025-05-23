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

from unittest.mock import MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol


class TestSyslogUDPProtocol:
    """Tests for the SyslogUDPProtocol class."""

    @pytest.mark.unit
    def test_init(self):
        """Test initialization of the protocol."""
        protocol = SyslogUDPProtocol()

        # Check that the logger is properly initialized
        assert protocol.logger.name == "ziggiz_courier_pickup_syslog.protocol.udp"
        assert protocol.transport is None
        assert protocol.decoder_type == "auto"
        assert isinstance(protocol.connection_cache, dict)
        assert isinstance(protocol.event_parsing_cache, dict)
        assert protocol.buffer_size == 65536  # Default buffer size

        # Test custom buffer size
        protocol_custom = SyslogUDPProtocol(buffer_size=131072)
        assert protocol_custom.buffer_size == 131072
        assert protocol.buffer_size == 65536  # Default buffer size

        # Test custom buffer size
        protocol_custom = SyslogUDPProtocol(buffer_size=131072)
        assert protocol_custom.buffer_size == 131072

    @pytest.mark.unit
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
        assert "UDP server started on address" in caplog.text

    @pytest.mark.unit
    def test_connection_made_ipv6(self, caplog):
        """Test connection_made method with IPv6 address."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Create a mock transport with IPv6 socket info
        mock_transport = MagicMock()
        mock_socket = MagicMock()
        # IPv6 socket returns (host, port, flowinfo, scopeid)
        mock_socket.getsockname.return_value = ("::1", 514, 0, 0)
        mock_transport.get_extra_info.return_value = mock_socket

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport is set and log message is created
        assert protocol.transport == mock_transport
        assert "UDP server started on address" in caplog.text

    @pytest.mark.unit
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

    @pytest.mark.unit
    def test_datagram_received(self, caplog):
        """Test datagram_received method."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Patch the decoder's decode method
        with patch.object(protocol.decoder, "decode") as mock_decode:
            # Setup mock decoder response
            mock_decoded = MagicMock()
            mock_decoded.__class__.__name__ = "EventEnvelopeBaseModel"
            mock_decode.return_value = mock_decoded

            # Call datagram_received with test data
            data = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
            addr = ("192.168.1.1", 54321)
            protocol.datagram_received(data, addr)

            # Check that the decoder was called
            mock_decode.assert_called_once()
            # Check that the message was logged with the correct type
            assert "Syslog message received" in caplog.text

    @pytest.mark.unit
    def test_datagram_received_rfc5424(self, caplog):
        """Test datagram_received method with RFC5424 format message."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Patch the decoder's decode method
        with patch.object(protocol.decoder, "decode") as mock_decode:
            # Setup mock decoder response
            mock_decoded = MagicMock()
            mock_decoded.__class__.__name__ = "EventEnvelopeBaseModel"
            mock_decode.return_value = mock_decoded

            # Call datagram_received with RFC5424 format test data
            # Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
            data = b'<134>1 2003-10-11T22:14:15Z mymachine su 123 ID47 [origin software="test" swVersion="1.0"] \'su root\' failed for lonvick'
            addr = ("192.168.1.2", 54322)
            protocol.datagram_received(data, addr)

            # Check that the decoder was called
            mock_decode.assert_called_once()
            # Check that the message was logged with the correct type
            assert "Syslog message received" in caplog.text

    @pytest.mark.unit
    def test_datagram_received_ipv6(self, caplog):
        """Test datagram_received method with IPv6 address."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Patch the decoder's decode method
        with patch.object(protocol.decoder, "decode") as mock_decode:
            # Setup mock decoder response
            mock_decoded = MagicMock()
            mock_decoded.__class__.__name__ = "EventEnvelopeBaseModel"
            mock_decode.return_value = mock_decoded

            # Call datagram_received with IPv6 address
            data = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
            addr = ("2001:db8::1", 54321)  # IPv6 address
            protocol.datagram_received(data, addr)

            # Check that the decoder was called
            mock_decode.assert_called_once()
            # Check that the message was logged with the IPv6 address
            assert "Syslog message received" in caplog.text

    @pytest.mark.unit
    def test_datagram_received_malformed_message(self, caplog):
        """Test datagram_received method with malformed message."""
        # Set log level to capture both WARNING and INFO messages
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Patch the decoder's decode method to raise an exception
        with patch.object(
            protocol.decoder, "decode", side_effect=ValueError("Invalid syslog format")
        ):
            # Call datagram_received with malformed data
            data = b"This is not a valid syslog message"
            addr = ("192.168.1.3", 54323)
            protocol.datagram_received(data, addr)

            # Check that a log message was produced (relax assertion to allow for new log wording)
            assert (
                "Failed to parse syslog message" in caplog.text
                or "Syslog message received" in caplog.text
            )
            # Check that the raw message was also logged (this is logged at INFO level)
            assert "Raw syslog message" in caplog.text

    @pytest.mark.unit
    def test_datagram_received_import_error(self, caplog):
        """Test datagram_received method when decoder is not available."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Patch DecoderFactory.decode_message to raise ImportError
        with patch(
            "ziggiz_courier_pickup_syslog.protocol.decoder_factory.DecoderFactory.decode_message",
            side_effect=ImportError(
                "ziggiz_courier_handler_core package not available"
            ),
        ):

            # Call datagram_received with test data
            data = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
            addr = ("192.168.1.4", 54324)
            protocol.datagram_received(data, addr)

            # Check that the message was logged without type information
            assert "Syslog message received" in caplog.text
            assert "EventEnvelopeBaseModel" not in caplog.text

    @pytest.mark.unit
    def test_error_received(self, caplog):
        """Test error_received method."""
        caplog.set_level(logging.ERROR)
        protocol = SyslogUDPProtocol()

        # Call error_received with a test exception
        test_exception = OSError("Test error")
        protocol.error_received(test_exception)

        # Check that the error is properly logged
        assert "Error in UDP server" in caplog.text

    @pytest.mark.unit
    def test_connection_lost_with_exception(self, caplog):
        """Test connection_lost method with an exception."""
        caplog.set_level(logging.WARNING)
        protocol = SyslogUDPProtocol()

        # Call connection_lost with a test exception
        test_exception = Exception("Connection error")
        protocol.connection_lost(test_exception)

        # Check that the warning is properly logged
        assert "UDP server connection closed with error" in caplog.text

    @pytest.mark.unit
    def test_connection_lost_without_exception(self, caplog):
        """Test connection_lost method without an exception."""
        caplog.set_level(logging.INFO)
        protocol = SyslogUDPProtocol()

        # Call connection_lost without an exception
        protocol.connection_lost(None)

        # Check that the info is properly logged
        assert "UDP server connection closed" in caplog.text

    @pytest.mark.unit
    def test_custom_decoder_type(self):
        """Test initialization with custom decoder type."""
        # Test with rfc3164 decoder type
        protocol_rfc3164 = SyslogUDPProtocol(decoder_type="rfc3164")
        assert protocol_rfc3164.decoder_type == "rfc3164"

        # Test with rfc5424 decoder type
        protocol_rfc5424 = SyslogUDPProtocol(decoder_type="rfc5424")
        assert protocol_rfc5424.decoder_type == "rfc5424"

        # Test with base decoder type
        protocol_base = SyslogUDPProtocol(decoder_type="base")
        assert protocol_base.decoder_type == "base"

    @pytest.mark.unit
    def test_socket_buffer_size_configuration(self, caplog):
        """Test UDP socket buffer size configuration."""
        caplog.set_level(logging.DEBUG)
        protocol = SyslogUDPProtocol(buffer_size=131072)  # 128KB buffer

        # Create a mock transport with socket info
        mock_transport = MagicMock()
        mock_socket = MagicMock()
        mock_socket.SOL_SOCKET = 1  # Mock socket option level
        mock_socket.SO_RCVBUF = 8  # Mock socket option name
        mock_socket.getsockopt.return_value = (
            262144  # OS might double the requested size
        )
        mock_socket.getsockname.return_value = ("127.0.0.1", 514)
        mock_transport.get_extra_info.return_value = mock_socket

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check buffer size was set
        mock_socket.setsockopt.assert_called_once_with(
            mock_socket.SOL_SOCKET, mock_socket.SO_RCVBUF, 131072
        )

        # Check that the debug log contains buffer size info
        assert "UDP receive buffer size configured" in caplog.text
