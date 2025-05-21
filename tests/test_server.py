# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the syslog server implementation

# Standard library imports
import asyncio
import logging

from unittest.mock import AsyncMock, MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.config import Config
from ziggiz_courier_pickup_syslog.server import SyslogServer


@pytest.mark.asyncio
class TestSyslogServer:
    """Tests for the SyslogServer class."""

    async def test_init(self):
        """Test initialization of the server."""
        # Test with default config
        server = SyslogServer()
        assert server.logger.name == "ziggiz_courier_pickup_syslog.server"
        assert isinstance(server.config, Config)
        assert server.loop is None
        assert server.udp_transport is None
        assert server.udp_protocol is None
        assert server.tcp_server is None

        # Test with custom config
        config = Config(host="127.0.0.1", port=1514, protocol="udp")
        server = SyslogServer(config)
        assert server.config == config

    async def test_start_tcp_server(self):
        """Test starting a TCP server."""
        config = Config(host="127.0.0.1", port=1514, protocol="tcp")
        server = SyslogServer(config)
        # Create a mock event loop and server
        mock_loop = AsyncMock()
        mock_server = AsyncMock()
        mock_loop.create_server.return_value = mock_server
        # Start the server
        server.loop = mock_loop
        result = await server.start_tcp_server("127.0.0.1", 1514)
        # Verify the result
        assert result == mock_server
        mock_loop.create_server.assert_called_once()
        # Check that the create_server was called with the correct protocol factory
        # and host/port arguments
        call_args = mock_loop.create_server.call_args
        # The first positional arg is the protocol factory
        assert call_args[0][1] == "127.0.0.1"  # host
        assert call_args[0][2] == 1514  # port

    async def test_start_udp_server(self):
        """Test starting a UDP server."""
        config = Config(host="127.0.0.1", port=1514, protocol="udp")
        server = SyslogServer(config)

        # Create mock objects
        mock_loop = AsyncMock()
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        mock_loop.create_datagram_endpoint.return_value = (
            mock_transport,
            mock_protocol,
        )

        # Start the server
        server.loop = mock_loop
        transport, protocol = await server.start_udp_server("127.0.0.1", 1514)

        # Verify the results
        assert transport == mock_transport
        assert protocol == mock_protocol
        mock_loop.create_datagram_endpoint.assert_called_once()
        args, kwargs = mock_loop.create_datagram_endpoint.call_args
        assert kwargs["local_addr"] == ("127.0.0.1", 1514)

    async def test_start_with_tcp(self):
        """Test starting the server with TCP protocol."""
        config = Config(host="127.0.0.1", port=1514, protocol="tcp")
        server = SyslogServer(config)

        # Mock the TCP server method
        mock_tcp_server = AsyncMock()
        server.start_tcp_server = AsyncMock(return_value=mock_tcp_server)

        # Start the server
        await server.start()

        # Verify the TCP server was started
        server.start_tcp_server.assert_called_once_with("127.0.0.1", 1514)
        assert server.tcp_server == mock_tcp_server
        assert server.udp_transport is None
        assert server.udp_protocol is None

    async def test_start_with_udp(self):
        """Test starting the server with UDP protocol."""
        config = Config(host="127.0.0.1", port=1514, protocol="udp")
        server = SyslogServer(config)

        # Mock the UDP server method
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        server.start_udp_server = AsyncMock(
            return_value=(mock_transport, mock_protocol)
        )

        # Start the server
        await server.start()

        # Verify the UDP server was started
        server.start_udp_server.assert_called_once_with("127.0.0.1", 1514)
        assert server.udp_transport == mock_transport
        assert server.udp_protocol == mock_protocol
        assert server.tcp_server is None

    async def test_start_invalid_protocol(self):
        """Test starting the server with an invalid protocol."""
        config = Config(host="127.0.0.1", port=1514)
        # Override the protocol validation to allow an invalid value
        config.protocol = "invalid"
        server = SyslogServer(config)

        # Start the server and expect an error
        with pytest.raises(RuntimeError):
            await server.start()

    async def test_stop_tcp(self, caplog):
        """Test stopping a TCP server."""
        caplog.set_level(logging.INFO)
        server = SyslogServer()
        # Use a mock server with proper async methods
        mock_server = MagicMock()  # Use regular MagicMock for non-async close
        # Ensure the mock has the necessary method for wait_closed
        mock_server.wait_closed = AsyncMock()  # Only wait_closed is async
        server.tcp_server = mock_server
        # Stop the server
        await server.stop()
        # Verify the server was closed
        mock_server.close.assert_called_once()
        mock_server.wait_closed.assert_called_once()
        assert server.tcp_server is None
        assert "Stopping syslog server" in caplog.text

    async def test_stop_udp(self, caplog):
        """Test stopping a UDP server."""
        caplog.set_level(logging.INFO)
        server = SyslogServer()
        # Create mocks for transport and protocol
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        server.udp_transport = mock_transport
        server.udp_protocol = mock_protocol
        # Stop the server
        await server.stop()
        # Verify the transport was closed
        mock_transport.close.assert_called_once()
        assert server.udp_transport is None
        assert server.udp_protocol is None
        assert "Stopping syslog server" in caplog.text

    @patch("asyncio.sleep")
    async def test_run_forever(self, mock_sleep):
        """Test the run_forever method."""
        server = SyslogServer()
        server.start = AsyncMock()
        server.stop = AsyncMock()
        # Mock sleep to raise CancelledError to exit the loop
        mock_sleep.side_effect = asyncio.CancelledError()
        # Run the server
        await server.run_forever()
        # Verify start and stop were called
        server.start.assert_called_once()
        server.stop.assert_called_once()
