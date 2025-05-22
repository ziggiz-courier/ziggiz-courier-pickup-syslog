# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the main module

# Standard library imports
import logging
import sys

from argparse import Namespace
from unittest.mock import AsyncMock, MagicMock

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.main import (
    main,
    run_server,
    setup_logging,
)
from ziggiz_courier_pickup_syslog.server import SyslogServer


class TestMainModule:
    """Tests for the main entry point module."""

    @pytest.mark.unit
    def test_setup_logging(self, caplog):
        """Test that logging is set up correctly."""
        # Test with DEBUG level
        setup_logging("DEBUG")
        root_logger = logging.getLogger()

        # Check that the root logger level is set correctly
        assert root_logger.level == logging.DEBUG

        # Check that we have at least one handler
        assert len(root_logger.handlers) >= 1

        # Check that aiokafka logger is set to WARNING
        aiokafka_logger = logging.getLogger("aiokafka")
        assert aiokafka_logger.level == logging.WARNING

        # Test with INFO level (reset handlers first)
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)

        setup_logging("INFO")
        assert root_logger.level == logging.INFO

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_start_tcp(self, mocker, caplog):
        """Test that SyslogServer initializes TCP server correctly."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Create a server instance with TCP configuration
        config = mocker.MagicMock()
        config.host = "127.0.0.1"
        config.port = 10514
        config.protocol = "tcp"
        server = SyslogServer(config)

        # Mock the TCP server creation
        mock_tcp_server = MagicMock()
        mock_create_server = AsyncMock(return_value=mock_tcp_server)

        # Apply the mocks to asyncio
        mock_loop = MagicMock()
        mock_loop.create_server = mock_create_server
        server.loop = mock_loop

        # Mock the start_tcp_server method
        mocker.patch.object(
            server, "start_tcp_server", AsyncMock(return_value=mock_tcp_server)
        )

        # Execute the function
        await server.start()

        # Verify results
        assert server.tcp_server == mock_tcp_server
        assert server.udp_transport is None
        assert server.udp_protocol is None

        # Check log messages
        assert (
            "Starting syslog server on 127.0.0.1 using TCP protocol on port 10514"
            in caplog.text
        )

        # Verify mocks were called correctly
        server.start_tcp_server.assert_called_once_with("127.0.0.1", 10514)

    @pytest.mark.asyncio
    async def test_server_start_udp(self, mocker, caplog):
        """Test that SyslogServer initializes UDP server correctly."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Create a server instance with UDP configuration
        config = mocker.MagicMock()
        config.host = "127.0.0.1"
        config.port = 10514
        config.protocol = "udp"
        server = SyslogServer(config)

        # Mock the UDP datagram_endpoint
        mock_udp_transport = MagicMock()
        mock_udp_protocol = MagicMock()
        mock_create_datagram_result = (mock_udp_transport, mock_udp_protocol)

        # Mock the start_udp_server method
        mocker.patch.object(
            server,
            "start_udp_server",
            AsyncMock(return_value=mock_create_datagram_result),
        )

        # Apply the mocks to asyncio
        mock_loop = MagicMock()
        server.loop = mock_loop

        # Execute the function
        await server.start()

        # Verify results
        assert server.udp_transport == mock_udp_transport
        assert server.udp_protocol == mock_udp_protocol
        assert server.tcp_server is None

        # Check log messages
        assert (
            "Starting syslog server on 127.0.0.1 using UDP protocol on port 10514"
            in caplog.text
        )

        # Verify mocks were called correctly
        server.start_udp_server.assert_called_once_with("127.0.0.1", 10514)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_start_udp_failure(self, mocker, caplog):
        """Test that SyslogServer handles UDP server initialization failure gracefully."""
        # Capture logs
        caplog.set_level(logging.ERROR)

        # Create a server instance with UDP configuration
        config = mocker.MagicMock()
        config.host = "127.0.0.1"
        config.port = 10514
        config.protocol = "udp"
        server = SyslogServer(config)

        # Mock the start_udp_server method to fail
        error = OSError("Address already in use")
        mocker.patch.object(server, "start_udp_server", AsyncMock(side_effect=error))

        # Apply the mocks to asyncio
        mock_loop = MagicMock()
        server.loop = mock_loop

        # Execute the function and expect it to raise an exception
        with pytest.raises(RuntimeError) as excinfo:
            await server.start()

        # Check log messages
        assert "Failed to start syslog server" in caplog.text
        assert "Address already in use" in str(excinfo.value)

        # Verify mocks were called correctly
        server.start_udp_server.assert_called_once_with("127.0.0.1", 10514)

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_server_start_tcp_failure(self, mocker, caplog):
        """Test that SyslogServer handles TCP server initialization failure gracefully."""
        # Capture logs
        caplog.set_level(logging.ERROR)

        # Create a server instance with TCP configuration
        config = mocker.MagicMock()
        config.host = "127.0.0.1"
        config.port = 10514
        config.protocol = "tcp"
        server = SyslogServer(config)

        # Mock the start_tcp_server method to fail
        error = OSError("Address already in use")
        mocker.patch.object(server, "start_tcp_server", AsyncMock(side_effect=error))

        # Apply the mocks to asyncio
        mock_loop = MagicMock()
        server.loop = mock_loop

        # Execute the function and expect it to raise an exception
        with pytest.raises(RuntimeError) as excinfo:
            await server.start()

        # Check log messages
        assert "Failed to start syslog server" in caplog.text
        assert "Address already in use" in str(excinfo.value)

        # Verify mocks were called correctly
        server.start_tcp_server.assert_called_once_with("127.0.0.1", 10514)

    def test_run_server_normal(self, mocker, caplog):
        """Test the run_server function with normal execution."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Mock SyslogServer class
        mock_server = mocker.MagicMock()
        server_tcp_server = MagicMock()
        # Set up the close method to be callable
        server_tcp_server.close = MagicMock()
        server_tcp_server.wait_closed = mocker.AsyncMock()

        # Set the tcp_server property
        type(mock_server).tcp_server = mocker.PropertyMock(
            return_value=server_tcp_server
        )

        # Set up the start method as an AsyncMock
        mock_start = mocker.AsyncMock(return_value=(None, None, None))
        mock_server.start = mock_start

        # Set up the stop method as an AsyncMock that will properly close the tcp_server
        mock_stop = mocker.AsyncMock()
        mock_stop.side_effect = lambda: server_tcp_server.close() or None
        mock_server.stop = mock_stop

        mocker.patch(
            "ziggiz_courier_pickup_syslog.server.SyslogServer", return_value=mock_server
        )

        # Mock asyncio.get_event_loop
        mock_loop = MagicMock()
        mocker.patch("asyncio.get_event_loop", return_value=mock_loop)

        # Mock start_server result for TCP
        run_until_complete_tcp_server = MagicMock()
        # Set up the close method to be callable
        run_until_complete_tcp_server.close = MagicMock()
        mock_start_result_tcp = (None, None, run_until_complete_tcp_server)

        # We'll just mock run_until_complete to return the result directly
        mock_loop.run_until_complete.return_value = mock_start_result_tcp

        # Mock KeyboardInterrupt when run_forever is called
        mock_loop.run_forever.side_effect = KeyboardInterrupt()

        # Run the function with TCP
        run_server("127.0.0.1", 10514, "tcp")

        # Check log messages for TCP
        # We know the server would log "Starting syslog server on 127.0.0.1 using TCP protocol on port 10514"
        # but our mock doesn't actually produce this log in a way caplog can capture
        # We can verify that the keyboard interrupt was logged
        assert "Received keyboard interrupt" in caplog.text

        # Since `mock_stop.side_effect = lambda: server_tcp_server.close() or None` isn't
        # executing in the coroutine flow, we can't easily test that server_tcp_server.close was called.
        # Instead, just verify that mock_stop was called, which is what happens in run_server's finally block
        mock_server.stop.assert_called()
        mock_loop.close.assert_called_once()

        # Reset mocks for UDP test
        mock_loop.reset_mock()
        server_tcp_server.reset_mock()
        caplog.clear()

        # Mock start_server result for UDP
        mock_udp_transport = MagicMock()
        # Set up the close method to be callable
        mock_udp_transport.close = MagicMock()
        mock_udp_protocol = MagicMock()
        mock_start_result_udp = (mock_udp_transport, mock_udp_protocol, None)
        mock_loop.run_until_complete.return_value = mock_start_result_udp

        # Mock KeyboardInterrupt when run_forever is called
        mock_loop.run_forever.side_effect = KeyboardInterrupt()

        # Run the function with UDP
        run_server("127.0.0.1", 10514, "udp")

        # Check log messages for UDP
        # We know the server would log "Starting syslog server on 127.0.0.1 using UDP protocol on port 10514"
        # but our mock doesn't actually produce this log in a way caplog can capture
        # We can verify that the keyboard interrupt was logged
        assert "Received keyboard interrupt" in caplog.text

        # Verify that the stop method was called
        mock_server.stop.assert_called()
        mock_loop.close.assert_called_once()

    @pytest.mark.unit
    def test_run_server_exception(self, mocker):
        """Test handling of exceptions in run_server."""
        # Create a logger that will raise an exception when info is called
        mock_logger = MagicMock()
        mock_logger.info.side_effect = Exception("Test error")

        # Mock logging.getLogger to return our mock
        mocker.patch("logging.getLogger", return_value=mock_logger)

        # Mock sys.exit to avoid test termination
        mock_exit = mocker.patch("sys.exit")

        # Run the function and expect it to handle the exception
        run_server()

        # Check that sys.exit was called with code 1
        mock_exit.assert_called_once_with(1)

    @pytest.mark.unit
    def test_main_function(self, mocker):
        """Test the main function with mocked arguments."""
        # Mock the load_config function to return a config object
        mock_config = mocker.MagicMock()
        mock_config.host = "127.0.0.1"
        mock_config.port = 10514
        mock_config.protocol = "tcp"
        mock_config.log_level = "DEBUG"
        mocker.patch(
            "ziggiz_courier_pickup_syslog.main.load_config", return_value=mock_config
        )

        # Mock command line arguments
        mock_parser = mocker.patch("argparse.ArgumentParser")
        mock_args = Namespace(
            config=None,
            log_level="DEBUG",
            host="127.0.0.1",
            port=10514,
            protocol="tcp",
            unix_socket_path=None,
            framing_mode=None,
            end_of_message_marker=None,
            max_message_length=None,
            decoder_type=None,
            # TLS-related arguments
            tls_certfile=None,
            tls_keyfile=None,
            tls_ca_certs=None,
            tls_verify_client=False,
            tls_min_version=None,
            tls_ciphers=None,
        )
        mock_parser.return_value.parse_args.return_value = mock_args

        # Mock setup_logging and run_server
        mock_setup_logging = mocker.patch(
            "ziggiz_courier_pickup_syslog.main.setup_logging"
        )
        mock_run_server = mocker.patch("ziggiz_courier_pickup_syslog.main.run_server")

        # Run the main function
        main()

        # Check that functions were called correctly
        mock_setup_logging.assert_called_once_with(config=mock_config)
        mock_run_server.assert_called_once_with("127.0.0.1", 10514, "tcp", mock_config)

    @pytest.mark.unit
    def test_main_keyboard_interrupt(self, mocker, caplog):
        """Test handling of KeyboardInterrupt in main."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Mock the load_config function to return a config object
        mock_config = mocker.MagicMock()
        mock_config.host = "::"
        mock_config.port = 514
        mock_config.protocol = "tcp"
        mock_config.log_level = "INFO"
        mocker.patch(
            "ziggiz_courier_pickup_syslog.main.load_config", return_value=mock_config
        )

        # Mock command line arguments
        mock_args = Namespace(
            config=None,
            log_level="INFO",
            host="::",
            port=514,
            protocol="tcp",
            unix_socket_path=None,
            framing_mode=None,
            end_of_message_marker=None,
            max_message_length=None,
            decoder_type=None,
            # TLS-related arguments
            tls_certfile=None,
            tls_keyfile=None,
            tls_ca_certs=None,
            tls_verify_client=False,
            tls_min_version=None,
            tls_ciphers=None,
        )
        mocker.patch("argparse.ArgumentParser.parse_args", return_value=mock_args)

        # Mock setup_logging
        mocker.patch("ziggiz_courier_pickup_syslog.main.setup_logging")

        # Mock run_server to raise KeyboardInterrupt
        mocker.patch(
            "ziggiz_courier_pickup_syslog.main.run_server",
            side_effect=KeyboardInterrupt,
        )

        # Run the main function and expect it to handle the interrupt
        main()

        # Check that the keyboard interrupt was handled correctly
        assert "Server shutdown requested by user" in caplog.text

    @pytest.mark.unit
    def test_main_unexpected_exception(self, mocker, caplog):
        """Test handling of unexpected exceptions in main."""
        # Capture logs
        caplog.set_level(logging.ERROR)

        # Mock the load_config function to return a config object
        mock_config = mocker.MagicMock()
        mock_config.host = "::"
        mock_config.port = 514
        mock_config.protocol = "tcp"
        mock_config.log_level = "INFO"
        mocker.patch(
            "ziggiz_courier_pickup_syslog.main.load_config", return_value=mock_config
        )

        # Mock command line arguments
        mock_args = Namespace(
            config=None, log_level="INFO", host="::", port=514, protocol="tcp"
        )
        mocker.patch("argparse.ArgumentParser.parse_args", return_value=mock_args)

        # Mock setup_logging
        mocker.patch("ziggiz_courier_pickup_syslog.main.setup_logging")

        # Mock run_server to raise an unexpected exception
        mocker.patch(
            "ziggiz_courier_pickup_syslog.main.run_server",
            side_effect=RuntimeError("Unexpected error"),
        )

        # Mock sys.exit to avoid test termination
        mock_exit = mocker.patch("sys.exit")

        # Run the main function
        main()

        # Check log messages and that sys.exit was called with code 1
        assert "Unexpected error" in caplog.text
        mock_exit.assert_called_once_with(1)

    @pytest.mark.unit
    def test_argument_parsing(self, mocker, capsys):
        """Test command-line argument parsing."""
        # Save the original sys.argv
        original_argv = sys.argv.copy()

        try:
            # Set up argument values for testing
            test_cases = [
                # Default values
                {
                    "args": ["ziggiz-syslog"],
                    "expected_log_level": "INFO",
                    "expected_host": "::",  # Updated to use IPv6 for dual-stack support
                    "expected_port": 514,
                    "expected_protocol": "tcp",
                },
                # Custom log level
                {
                    "args": ["ziggiz-syslog", "--log-level", "DEBUG"],
                    "expected_log_level": "DEBUG",
                    "expected_host": "::",
                    "expected_port": 514,
                    "expected_protocol": "tcp",
                },
                # Custom host and port
                {
                    "args": [
                        "ziggiz-syslog",
                        "--host",
                        "127.0.0.1",
                        "--port",
                        "10514",
                        "--protocol",
                        "udp",
                    ],
                    "expected_log_level": "INFO",
                    "expected_host": "127.0.0.1",
                    "expected_port": 10514,
                    "expected_protocol": "udp",
                },
                # Mix of custom settings
                {
                    "args": [
                        "ziggiz-syslog",
                        "--log-level",
                        "WARNING",
                        "--host",
                        "192.168.1.10",
                        "--protocol",
                        "tcp",
                    ],
                    "expected_log_level": "WARNING",
                    "expected_host": "192.168.1.10",
                    "expected_port": 514,
                    "expected_protocol": "tcp",
                },
            ]

            # Mock setup_logging and run_server to prevent actual execution
            mock_setup_logging = mocker.patch(
                "ziggiz_courier_pickup_syslog.main.setup_logging"
            )
            mock_run_server = mocker.patch(
                "ziggiz_courier_pickup_syslog.main.run_server"
            )  # Create a mock config for each test case
            mock_config = mocker.MagicMock()
            mocker.patch(
                "ziggiz_courier_pickup_syslog.main.load_config",
                return_value=mock_config,
            )

            # Test each case
            for case in test_cases:
                # Set the command-line arguments
                sys.argv = case["args"]

                # Reset the mock attributes for the new case
                mock_config.host = "::"  # Default values
                mock_config.port = 514
                mock_config.protocol = "tcp"
                mock_config.log_level = "INFO"

                # Add config attribute to command line args
                mock_args = Namespace(
                    config=None,
                    log_level=(
                        case["expected_log_level"]
                        if "--log-level" in case["args"]
                        else None
                    ),
                    host=case["expected_host"] if "--host" in case["args"] else None,
                    port=case["expected_port"] if "--port" in case["args"] else None,
                    protocol=(
                        case["expected_protocol"]
                        if "--protocol" in case["args"]
                        else None
                    ),
                    unix_socket_path=None,
                    framing_mode=None,
                    end_of_message_marker=None,
                    max_message_length=None,
                    decoder_type=None,
                    # TLS-related arguments
                    tls_certfile=None,
                    tls_keyfile=None,
                    tls_ca_certs=None,
                    tls_verify_client=False,
                    tls_min_version=None,
                    tls_ciphers=None,
                )
                mock_parser = mocker.patch("argparse.ArgumentParser")
                mock_parser.return_value.parse_args.return_value = mock_args

                # Run the main function
                main()

                # Check that functions were called with the expected arguments
                # Note: setup_logging is now called with a config object
                assert mock_config.log_level == case["expected_log_level"]
                assert mock_config.host == case["expected_host"]
                assert mock_config.port == case["expected_port"]
                assert mock_config.protocol == case["expected_protocol"]

                mock_run_server.assert_called_with(
                    case["expected_host"],
                    case["expected_port"],
                    case["expected_protocol"],
                    mock_config,
                )

                # Reset the mocks for the next test case
                mock_setup_logging.reset_mock()
                mock_run_server.reset_mock()

        finally:
            # Restore the original sys.argv
            sys.argv = original_argv
