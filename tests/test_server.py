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
import ssl

from unittest.mock import AsyncMock, MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.config import Config
from ziggiz_courier_pickup_syslog.server import SyslogServer


@pytest.mark.integration
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
        assert server.unix_server is None
        assert server.tls_server is None
        assert server.tls_context is None

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

    async def test_start_unix_server(self):
        """Test starting a Unix server."""
        config = Config(protocol="unix", unix_socket_path="/tmp/test-socket.sock")
        server = SyslogServer(config)

        # Create a mock event loop and server
        mock_loop = AsyncMock()
        mock_server = AsyncMock()
        mock_loop.create_unix_server.return_value = mock_server

        # Start the server
        server.loop = mock_loop
        result = await server.start_unix_server("/tmp/test-socket.sock")

        # Verify the result
        assert result == mock_server
        mock_loop.create_unix_server.assert_called_once()
        # Check that create_unix_server was called with the correct protocol factory
        # and socket path arguments
        call_args = mock_loop.create_unix_server.call_args
        assert call_args[0][1] == "/tmp/test-socket.sock"  # socket path

    @patch(
        "ziggiz_courier_pickup_syslog.protocol.tls.TLSContextBuilder.create_server_context"
    )
    async def test_start_tls_server(self, mock_create_context):
        """Test starting a TLS server."""
        # Create a configuration with TLS settings
        config = Config(
            host="127.0.0.1",
            port=6514,
            protocol="tls",
            tls_certfile="/path/to/cert.pem",
            tls_keyfile="/path/to/key.pem",
            tls_ca_certs="/path/to/ca.pem",
            tls_verify_client=True,
            tls_min_version="TLSv1_2",
            tls_ciphers="HIGH:!aNULL:!MD5",
        )
        server = SyslogServer(config)

        # Create mock objects
        mock_loop = AsyncMock()
        mock_server = AsyncMock()
        mock_context = MagicMock()
        mock_cert_verifier = MagicMock()
        mock_loop.create_server.return_value = mock_server
        mock_create_context.return_value = (mock_context, mock_cert_verifier)

        # Start the server
        server.loop = mock_loop
        result_server, result_context = await server.start_tls_server("127.0.0.1", 6514)

        # Verify the results
        assert result_server == mock_server
        assert result_context == mock_context

        # Verify the context was created with the correct parameters
        mock_create_context.assert_called_once_with(
            certfile="/path/to/cert.pem",
            keyfile="/path/to/key.pem",
            ca_certs="/path/to/ca.pem",
            verify_client=True,
            min_version=ssl.TLSVersion.TLSv1_2,
            ciphers="HIGH:!aNULL:!MD5",
            cert_rules=None,
        )

        # Verify the server was created with the correct parameters
        mock_loop.create_server.assert_called_once()
        call_args = mock_loop.create_server.call_args
        assert call_args[0][1] == "127.0.0.1"  # host
        assert call_args[0][2] == 6514  # port
        assert call_args[1]["ssl"] == mock_context  # ssl context

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

    async def test_start_with_unix(self):
        """Test starting the server with Unix protocol."""
        socket_path = "/tmp/test-syslog.sock"
        config = Config(protocol="unix", unix_socket_path=socket_path)
        server = SyslogServer(config)

        # Mock the Unix server method
        mock_unix_server = AsyncMock()
        server.start_unix_server = AsyncMock(return_value=mock_unix_server)

        # Start the server
        await server.start()

        # Verify the Unix server was started
        server.start_unix_server.assert_called_once_with(socket_path)
        assert server.unix_server == mock_unix_server
        assert server.udp_transport is None
        assert server.udp_protocol is None
        assert server.tcp_server is None
        assert server.tls_server is None

    async def test_start_with_tls(self):
        """Test starting the server with TLS protocol."""
        config = Config(
            host="127.0.0.1",
            port=6514,
            protocol="tls",
            tls_certfile="/path/to/cert.pem",
            tls_keyfile="/path/to/key.pem",
        )
        server = SyslogServer(config)

        # Mock the TLS server method
        mock_tls_server = AsyncMock()
        mock_tls_context = MagicMock()
        server.start_tls_server = AsyncMock(
            return_value=(mock_tls_server, mock_tls_context)
        )

        # Start the server
        await server.start()

        # Verify the TLS server was started
        server.start_tls_server.assert_called_once_with("127.0.0.1", 6514)
        assert server.tls_server == mock_tls_server
        assert server.tls_context == mock_tls_context
        assert server.udp_transport is None
        assert server.udp_protocol is None
        assert server.tcp_server is None
        assert server.unix_server is None

    async def test_start_tls_missing_cert(self):
        """Test starting the server with TLS protocol but missing certificate."""
        config = Config(protocol="tls", tls_certfile=None, tls_keyfile=None)
        server = SyslogServer(config)

        # Start the server and expect an error
        with pytest.raises(RuntimeError):
            await server.start()

    async def test_start_invalid_protocol(self):
        """Test starting the server with an invalid protocol."""
        config = Config(host="127.0.0.1", port=1514)
        # Override the protocol validation to allow an invalid value
        config.protocol = "invalid"
        server = SyslogServer(config)

        # Start the server and expect an error
        with pytest.raises(RuntimeError):
            await server.start()

    async def test_start_unix_missing_path(self):
        """Test starting the server with Unix protocol but missing socket path."""
        config = Config(protocol="unix", unix_socket_path=None)
        server = SyslogServer(config)

        # Start the server and expect an error
        with pytest.raises(RuntimeError):
            await server.start()

    async def test_stop_tcp(self):
        """Test stopping a TCP server (functional, not log output)."""
        server = SyslogServer()
        mock_server = MagicMock()
        mock_server.wait_closed = AsyncMock()
        server.tcp_server = mock_server
        await server.stop()
        mock_server.close.assert_called_once()
        mock_server.wait_closed.assert_called_once()
        assert server.tcp_server is None

    async def test_stop_udp(self):
        """Test stopping a UDP server (functional, not log output)."""
        server = SyslogServer()
        mock_transport = MagicMock()
        mock_protocol = MagicMock()
        server.udp_transport = mock_transport
        server.udp_protocol = mock_protocol
        await server.stop()
        mock_transport.close.assert_called_once()
        assert server.udp_transport is None
        assert server.udp_protocol is None

    async def test_stop_unix(self):
        """Test stopping a Unix server (functional, not log output)."""
        server = SyslogServer()
        socket_path = "/tmp/test-syslog.sock"
        server.config = Config(protocol="unix", unix_socket_path=socket_path)
        mock_server = MagicMock()
        mock_server.wait_closed = AsyncMock()
        server.unix_server = mock_server
        with patch("os.path.exists") as mock_exists, patch("os.unlink") as mock_unlink:
            mock_exists.return_value = True
            await server.stop()
            mock_server.close.assert_called_once()
            mock_server.wait_closed.assert_called_once()
            assert server.unix_server is None
            mock_unlink.assert_called_once_with(socket_path)

    async def test_stop_tls(self):
        """Test stopping a TLS server (functional, not log output)."""
        server = SyslogServer()
        mock_server = MagicMock()
        mock_server.wait_closed = AsyncMock()
        mock_context = MagicMock()
        server.tls_server = mock_server
        server.tls_context = mock_context
        await server.stop()
        mock_server.close.assert_called_once()
        mock_server.wait_closed.assert_called_once()
        assert server.tls_server is None
        assert server.tls_context is None

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
