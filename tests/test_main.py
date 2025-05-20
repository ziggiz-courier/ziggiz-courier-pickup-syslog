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
from unittest.mock import MagicMock

# Local/package imports
from ziggiz_courier_pickup_syslog.main import main, run_server, setup_logging


class TestMainModule:
    """Tests for the main entry point module."""

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

    def test_run_server_normal(self, mocker, caplog):
        """Test the run_server function with normal execution."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Run the function
        run_server()

        # Check log messages
        assert "Starting syslog server" in caplog.text

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

    def test_main_function(self, mocker):
        """Test the main function with mocked arguments."""
        # Mock command line arguments
        mock_parser = mocker.patch("argparse.ArgumentParser")
        mock_args = Namespace(log_level="DEBUG")
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
        mock_run_server.assert_called_once()

    def test_main_keyboard_interrupt(self, mocker, caplog):
        """Test handling of KeyboardInterrupt in main."""
        # Capture logs
        caplog.set_level(logging.INFO)

        # Mock command line arguments
        mock_args = Namespace(log_level="INFO")
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

    def test_main_unexpected_exception(self, mocker, caplog):
        """Test handling of unexpected exceptions in main."""
        # Capture logs
        caplog.set_level(logging.ERROR)

        # Mock command line arguments
        mock_args = Namespace(log_level="INFO")
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

    def test_argument_parsing(self, mocker, capsys):
        """Test command-line argument parsing."""
        # Save the original sys.argv
        original_argv = sys.argv.copy()

        try:
            # Set up argument values for testing
            test_cases = [
                # Default values
                {"args": ["ziggiz-syslog"], "expected_log_level": "INFO"},
                # Custom log level
                {
                    "args": ["ziggiz-syslog", "--log-level", "DEBUG"],
                    "expected_log_level": "DEBUG",
                },
                # Custom log level with warning
                {
                    "args": ["ziggiz-syslog", "--log-level", "WARNING"],
                    "expected_log_level": "WARNING",
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
                mock_run_server.assert_called_once()

                # Reset the mocks for the next test case
                mock_setup_logging.reset_mock()
                mock_run_server.reset_mock()

        finally:
            # Restore the original sys.argv
            sys.argv = original_argv
