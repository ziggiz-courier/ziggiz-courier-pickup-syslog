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
    start_servers,
)


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
    async def test_start_servers_success(self, mocker, caplog):
        """Test that start_servers initializes both UDP and TCP servers correctly."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Mock the UDP datagram_endpoint
        mock_udp_transport = MagicMock()
        mock_udp_protocol = MagicMock()
        mock_create_datagram = AsyncMock(
            return_value=(mock_udp_transport, mock_udp_protocol)
        )

        # Mock the TCP server
        mock_tcp_server = MagicMock()
        mock_create_server = AsyncMock(return_value=mock_tcp_server)

        # Apply the mocks to asyncio
        mock_loop = MagicMock()
        mock_loop.create_datagram_endpoint = mock_create_datagram
        mock_loop.create_server = mock_create_server

        # Execute the function
        result = await start_servers("127.0.0.1", 10514, 10515, loop=mock_loop)

        # Verify results
        assert result[0] == mock_udp_transport
        assert result[1] == mock_udp_protocol
        assert result[2] == mock_tcp_server

        # Check log messages
        assert "UDP server listening on 127.0.0.1:10514" in caplog.text
        assert "TCP server listening on 127.0.0.1:10515" in caplog.text

        # Verify mocks were called correctly
        mock_create_datagram.assert_called_once()
        mock_create_server.assert_called_once()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_start_servers_udp_failure(self, mocker, caplog):
        """Test that start_servers handles UDP server initialization failure gracefully."""
        # Capture logs
        caplog.set_level(logging.ERROR)

        # Mock the UDP datagram_endpoint to fail
        mock_create_datagram = AsyncMock(side_effect=OSError("Address already in use"))

        # Mock the TCP server to succeed
        mock_tcp_server = MagicMock()
        mock_create_server = AsyncMock(return_value=mock_tcp_server)

        # Apply the mocks to asyncio
        mock_loop = MagicMock()
        mock_loop.create_datagram_endpoint = mock_create_datagram
        mock_loop.create_server = mock_create_server

        # Execute the function
        result = await start_servers("127.0.0.1", 10514, 10515, loop=mock_loop)

        # Verify results
        assert result[0] is None
        assert result[1] is None
        assert result[2] == mock_tcp_server

        # Check log messages
        assert "Failed to start UDP server" in caplog.text
        assert "Address already in use" in caplog.text

        # Verify mocks were called correctly
        mock_create_datagram.assert_called_once()
        mock_create_server.assert_called_once()

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_start_servers_tcp_failure(self, mocker, caplog):
        """Test that start_servers handles TCP server initialization failure gracefully."""
        # Capture logs
        caplog.set_level(logging.ERROR)

        # Mock the UDP datagram_endpoint to succeed
        mock_udp_transport = MagicMock()
        mock_udp_protocol = MagicMock()
        mock_create_datagram = AsyncMock(
            return_value=(mock_udp_transport, mock_udp_protocol)
        )

        # Mock the TCP server to fail
        mock_create_server = AsyncMock(side_effect=OSError("Address already in use"))

        # Apply the mocks to asyncio
        mock_loop = MagicMock()
        mock_loop.create_datagram_endpoint = mock_create_datagram
        mock_loop.create_server = mock_create_server

        # Execute the function
        result = await start_servers("127.0.0.1", 10514, 10515, loop=mock_loop)

        # Verify results
        assert result[0] == mock_udp_transport
        assert result[1] == mock_udp_protocol
        assert result[2] is None

        # Check log messages
        assert "Failed to start TCP server" in caplog.text
        assert "Address already in use" in caplog.text

        # Verify mocks were called correctly
        mock_create_datagram.assert_called_once()
        mock_create_server.assert_called_once()

    @pytest.mark.unit
    def test_run_server_normal(self, mocker, caplog):
        """Test the run_server function with normal execution."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Mock asyncio.get_event_loop
        mock_loop = MagicMock()
        mocker.patch("asyncio.get_event_loop", return_value=mock_loop)

        # Mock start_servers result
        mock_udp_transport = MagicMock()
        mock_udp_protocol = MagicMock()
        mock_tcp_server = MagicMock()
        mock_start_result = (mock_udp_transport, mock_udp_protocol, mock_tcp_server)
        mock_loop.run_until_complete.return_value = mock_start_result

        # Mock KeyboardInterrupt when run_forever is called
        mock_loop.run_forever.side_effect = KeyboardInterrupt()

        # Run the function
        run_server("127.0.0.1", 10514, 10515)

        # Check log messages
        assert "Starting syslog server on 127.0.0.1" in caplog.text
        assert "UDP port 10514" in caplog.text
        assert "TCP port 10515" in caplog.text
        assert "Received keyboard interrupt" in caplog.text

        # Verify cleanup happened correctly
        mock_udp_transport.close.assert_called_once()
        mock_tcp_server.close.assert_called_once()
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
        # Mock command line arguments
        mock_parser = mocker.patch("argparse.ArgumentParser")
        mock_args = Namespace(
            log_level="DEBUG", host="127.0.0.1", udp_port=10514, tcp_port=10515
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
        mock_setup_logging.assert_called_once_with("DEBUG")
        mock_run_server.assert_called_once_with("127.0.0.1", 10514, 10515)

    @pytest.mark.unit
    def test_main_keyboard_interrupt(self, mocker, caplog):
        """Test handling of KeyboardInterrupt in main."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Mock command line arguments
        mock_args = Namespace(
            log_level="INFO", host="0.0.0.0", udp_port=514, tcp_port=514
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

        # Mock command line arguments
        mock_args = Namespace(
            log_level="INFO", host="0.0.0.0", udp_port=514, tcp_port=514
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
                    "expected_host": "0.0.0.0",
                    "expected_udp_port": 514,
                    "expected_tcp_port": 514,
                },
                # Custom log level
                {
                    "args": ["ziggiz-syslog", "--log-level", "DEBUG"],
                    "expected_log_level": "DEBUG",
                    "expected_host": "0.0.0.0",
                    "expected_udp_port": 514,
                    "expected_tcp_port": 514,
                },
                # Custom host and ports
                {
                    "args": [
                        "ziggiz-syslog",
                        "--host",
                        "127.0.0.1",
                        "--udp-port",
                        "10514",
                        "--tcp-port",
                        "10515",
                    ],
                    "expected_log_level": "INFO",
                    "expected_host": "127.0.0.1",
                    "expected_udp_port": 10514,
                    "expected_tcp_port": 10515,
                },
                # Mix of custom settings
                {
                    "args": [
                        "ziggiz-syslog",
                        "--log-level",
                        "WARNING",
                        "--host",
                        "192.168.1.10",
                        "--tcp-port",
                        "1514",
                    ],
                    "expected_log_level": "WARNING",
                    "expected_host": "192.168.1.10",
                    "expected_udp_port": 514,
                    "expected_tcp_port": 1514,
                },
            ]

            # Mock setup_logging and run_server to prevent actual execution
            mock_setup_logging = mocker.patch(
                "ziggiz_courier_pickup_syslog.main.setup_logging"
            )
            mock_run_server = mocker.patch(
                "ziggiz_courier_pickup_syslog.main.run_server"
            )

            # Test each case
            for case in test_cases:
                # Set the command-line arguments
                sys.argv = case["args"]

                # Run the main function
                main()

                # Check that functions were called with the expected arguments
                mock_setup_logging.assert_called_with(case["expected_log_level"])
                mock_run_server.assert_called_once_with(
                    case["expected_host"],
                    case["expected_udp_port"],
                    case["expected_tcp_port"],
                )

                # Reset the mocks for the next test case
                mock_setup_logging.reset_mock()
                mock_run_server.reset_mock()

        finally:
            # Restore the original sys.argv
            sys.argv = original_argv
