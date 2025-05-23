# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for framing integration with protocols

# Standard library imports

# Standard library imports
from unittest.mock import AsyncMock, MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.config import Config
from ziggiz_courier_pickup_syslog.protocol.framing import FramingMode

# Package imports
from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol
from ziggiz_courier_pickup_syslog.protocol.unix import SyslogUnixProtocol
from ziggiz_courier_pickup_syslog.server import SyslogServer


@pytest.mark.integration
class TestProtocolFramingIntegration:
    """Tests for the integration of framing helper with protocols."""

    def test_tcp_protocol_initialization_with_framing(self):
        """Test that TCP protocol initializes framing helper correctly."""
        # Test default initialization
        tcp_protocol = SyslogTCPProtocol()
        assert tcp_protocol.framing_helper is not None
        assert tcp_protocol.framing_helper.framing_mode == FramingMode.AUTO
        assert tcp_protocol.framing_helper.end_of_msg_marker == b"\n"

        # Test custom initialization
        tcp_protocol = SyslogTCPProtocol(
            framing_mode="transparent",
            end_of_message_marker="\\r\\n",
            max_message_length=8192,
            decoder_type="rfc5424",
        )
        assert tcp_protocol.framing_helper.framing_mode == FramingMode.TRANSPARENT
        assert tcp_protocol.framing_helper.end_of_msg_marker == b"\r\n"
        assert tcp_protocol.framing_helper.max_msg_length == 8192
        assert tcp_protocol.decoder_type == "rfc5424"

    def test_unix_protocol_initialization_with_framing(self):
        """Test that Unix protocol initializes framing helper correctly."""
        # Test default initialization
        unix_protocol = SyslogUnixProtocol()
        assert unix_protocol.framing_helper is not None
        assert unix_protocol.framing_helper.framing_mode == FramingMode.AUTO
        assert unix_protocol.framing_helper.end_of_msg_marker == b"\n"

        # Test custom initialization
        unix_protocol = SyslogUnixProtocol(
            framing_mode="non_transparent",
            end_of_message_marker="\\0",
            max_message_length=4096,
            decoder_type="rfc3164",
        )
        assert unix_protocol.framing_helper.framing_mode == FramingMode.NON_TRANSPARENT
        assert unix_protocol.framing_helper.end_of_msg_marker == b"\0"
        assert unix_protocol.framing_helper.max_msg_length == 4096
        assert unix_protocol.decoder_type == "rfc3164"

    def test_tcp_protocol_message_processing(self):
        """Test that TCP protocol processes messages correctly."""
        # Set up the protocol with a mock transport
        tcp_protocol = SyslogTCPProtocol(framing_mode="auto")
        tcp_protocol.logger = MagicMock()
        tcp_protocol.transport = MagicMock()
        tcp_protocol.peername = ("test-host", 12345)

        # Create a mock read buffer
        tcp_protocol._read_buffer = bytearray(b"11 Hello World")
        tcp_protocol.buffer_updated(len(b"11 Hello World"))

        # Check that the message was processed
        tcp_protocol.logger.info.assert_called_once()
        assert tcp_protocol.logger.info.call_args[0][0] == "Syslog message received"

    def test_unix_protocol_message_processing(self):
        """Test that Unix protocol processes messages correctly."""
        # Set up the protocol with a mock transport
        unix_protocol = SyslogUnixProtocol(framing_mode="auto")
        unix_protocol.logger = MagicMock()
        unix_protocol.transport = MagicMock()
        unix_protocol.peername = "test-peer"

        # Create a mock read buffer
        unix_protocol._read_buffer = bytearray(b"11 Hello World")
        unix_protocol.buffer_updated(len(b"11 Hello World"))

        # Check that the message was processed
        unix_protocol.logger.info.assert_called_once()
        assert unix_protocol.logger.info.call_args[0][0] == "Syslog message received"

    @pytest.mark.asyncio
    async def test_server_protocol_factory(self):
        """Test that server passes framing configuration to protocols."""
        # Mock the event loop for the server
        mock_loop = AsyncMock()

        # Create a configuration with custom framing options
        config = Config(
            framing_mode="transparent",
            end_of_message_marker="\\r\\n",
            max_message_length=4096,
            decoder_type="rfc5424",
        )

        server = SyslogServer(config=config)
        server.loop = mock_loop

        # Test TCP server
        mock_server = AsyncMock()
        mock_loop.create_server = AsyncMock(return_value=mock_server)

        await server.start_tcp_server("localhost", 12345)

        # Check that create_server was called with a protocol factory
        mock_loop.create_server.assert_called_once()
        # The first argument should be the protocol factory
        protocol_factory = mock_loop.create_server.call_args[0][0]
        assert callable(protocol_factory)

        # Check that the factory creates a protocol with the right configuration
        tcp_protocol = protocol_factory()
        assert tcp_protocol.framing_helper.framing_mode == FramingMode.TRANSPARENT
        assert tcp_protocol.framing_helper.end_of_msg_marker == b"\r\n"
        assert tcp_protocol.framing_helper.max_msg_length == 4096
        assert tcp_protocol.decoder_type == "rfc5424"

        # Test Unix server
        mock_loop.reset_mock()
        mock_loop.create_unix_server = AsyncMock(return_value=mock_server)

        # Patch os.path.exists and os.unlink to avoid file system operations
        with patch("os.path.exists", return_value=False), patch(
            "os.path.dirname", return_value=""
        ), patch("os.makedirs"):
            await server.start_unix_server("/tmp/test-socket")

        # Check that create_unix_server was called with a protocol factory
        mock_loop.create_unix_server.assert_called_once()
        # The first argument should be the protocol factory
        protocol_factory = mock_loop.create_unix_server.call_args[0][0]
        assert callable(protocol_factory)

        # Check that the factory creates a protocol with the right configuration
        unix_protocol = protocol_factory()
        assert unix_protocol.framing_helper.framing_mode == FramingMode.TRANSPARENT
        assert unix_protocol.framing_helper.end_of_msg_marker == b"\r\n"
        assert unix_protocol.framing_helper.max_msg_length == 4096
        assert unix_protocol.decoder_type == "rfc5424"
