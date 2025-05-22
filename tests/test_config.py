# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the configuration module

# Standard library imports
import logging

from unittest.mock import mock_open, patch

# Third-party imports
import pytest
import yaml

# Local/package imports
from ziggiz_courier_pickup_syslog.config import (
    Config,
    LoggerConfig,
    configure_logging,
    load_config,
)


class TestConfig:
    """Tests for the configuration module."""

    @pytest.mark.unit
    def test_config_defaults(self):
        """Test default configuration values."""
        config = Config()
        assert config.host == "::"
        assert config.protocol == "tcp"
        assert config.port == 514
        assert config.log_level == "INFO"
        assert config.loggers == []
        # Check framing defaults
        assert config.framing_mode == "auto"
        assert config.end_of_message_marker == "\\n"
        assert config.max_message_length == 16 * 1024
        # Check TLS defaults
        assert config.tls_certfile is None
        assert config.tls_keyfile is None
        assert config.tls_ca_certs is None
        assert config.tls_verify_client is False
        assert config.tls_min_version == "TLSv1_3"
        assert config.tls_ciphers is None

    @pytest.mark.unit
    def test_logger_config(self):
        """Test logger configuration."""
        logger_config = LoggerConfig(name="test.logger", level="DEBUG")
        assert logger_config.name == "test.logger"
        assert logger_config.level == "DEBUG"
        assert logger_config.propagate is True

    # No replacement needed - removing the test_decoder_config function

    @pytest.mark.unit
    def test_validate_log_level_valid(self):
        """Test validation of valid log levels."""
        config = Config(log_level="debug")  # lowercase should be converted to uppercase
        assert config.log_level == "DEBUG"

        config = Config(log_level="INFO")
        assert config.log_level == "INFO"

    @pytest.mark.unit
    def test_validate_log_level_invalid(self):
        """Test validation of invalid log levels."""
        with pytest.raises(ValueError):
            Config(log_level="INVALID_LEVEL")

    @pytest.mark.unit
    def test_validate_protocol_valid(self):
        """Test validation of valid protocol values."""
        config = Config(protocol="tcp")  # default value
        assert config.protocol == "tcp"

        config = Config(protocol="UDP")  # uppercase should be converted to lowercase
        assert config.protocol == "udp"

        config = Config(protocol="unix")
        assert config.protocol == "unix"

        config = Config(protocol="tls")
        assert config.protocol == "tls"

    @pytest.mark.unit
    def test_validate_protocol_invalid(self):
        """Test validation of invalid protocol values."""
        with pytest.raises(ValueError):
            Config(protocol="invalid_protocol")

    @pytest.mark.unit
    def test_validate_framing_mode_valid(self):
        """Test validation of valid framing mode values."""
        config = Config(framing_mode="auto")  # default value
        assert config.framing_mode == "auto"

        config = Config(
            framing_mode="TRANSPARENT"
        )  # uppercase should be converted to lowercase
        assert config.framing_mode == "transparent"

        config = Config(framing_mode="non_transparent")
        assert config.framing_mode == "non_transparent"

    @pytest.mark.unit
    def test_validate_framing_mode_invalid(self):
        """Test validation of invalid framing mode values."""
        with pytest.raises(ValueError):
            Config(framing_mode="invalid_mode")

    @pytest.mark.unit
    def test_validate_tls_min_version_valid(self):
        """Test validation of valid TLS version values."""
        config = Config(tls_min_version="TLSv1_3")  # default value
        assert config.tls_min_version == "TLSv1_3"

        config = Config(
            tls_min_version="tlsv1_2"
        )  # lowercase should be converted to uppercase
        assert config.tls_min_version == "TLSv1_2"

    @pytest.mark.unit
    def test_validate_tls_min_version_invalid(self):
        """Test validation of invalid TLS version values."""
        with pytest.raises(ValueError):
            Config(tls_min_version="TLSv1_1")

        with pytest.raises(ValueError):
            Config(tls_min_version="invalid_version")

    @pytest.mark.unit
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
host: "127.0.0.1"
protocol: "udp"
port: 1514
log_level: "DEBUG"
framing_mode: "transparent"
end_of_message_marker: "\\r\\n"
max_message_length: 8192
loggers:
  - name: "test.logger"
    level: "DEBUG"
    propagate: false
""",
    )
    @patch("pathlib.Path.exists")
    def test_load_config(self, mock_exists, mock_file):
        """Test loading configuration from a file."""
        mock_exists.return_value = True

        config = load_config("test_config.yaml")

        assert config.host == "127.0.0.1"
        assert config.protocol == "udp"
        assert config.port == 1514
        assert config.log_level == "DEBUG"

        assert len(config.loggers) == 1
        assert config.loggers[0].name == "test.logger"
        assert config.loggers[0].level == "DEBUG"
        assert config.loggers[0].propagate is False

    @pytest.mark.unit
    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data="""
host: "127.0.0.1"
protocol: "tls"
port: 6514
tls_certfile: "/path/to/cert.pem"
tls_keyfile: "/path/to/key.pem"
tls_ca_certs: "/path/to/ca.pem"
tls_verify_client: true
tls_min_version: "TLSv1_2"
tls_ciphers: "HIGH:!aNULL:!MD5"
log_level: "INFO"
""",
    )
    @patch("pathlib.Path.exists")
    def test_load_config_with_tls(self, mock_exists, mock_file):
        """Test loading TLS configuration from a file."""
        mock_exists.return_value = True

        config = load_config("tls_config.yaml")

        assert config.host == "127.0.0.1"
        assert config.protocol == "tls"
        assert config.port == 6514
        assert config.tls_certfile == "/path/to/cert.pem"
        assert config.tls_keyfile == "/path/to/key.pem"
        assert config.tls_ca_certs == "/path/to/ca.pem"
        assert config.tls_verify_client is True
        assert config.tls_min_version == "TLSv1_2"
        assert config.tls_ciphers == "HIGH:!aNULL:!MD5"

    @pytest.mark.unit
    @patch("builtins.open", side_effect=yaml.YAMLError("Invalid YAML"))
    @patch("pathlib.Path.exists")
    def test_load_config_invalid_yaml(self, mock_exists, mock_open):
        """Test handling of invalid YAML in config file."""
        mock_exists.return_value = True

        with pytest.raises(yaml.YAMLError):
            load_config("invalid_config.yaml")

    @pytest.mark.unit
    @patch("pathlib.Path.exists", return_value=False)
    def test_load_config_not_found(self, mock_exists):
        """Test handling of configuration file not found."""
        # When explicit config path is provided but file doesn't exist
        with pytest.raises(FileNotFoundError):
            load_config("non_existent_config.yaml")

        # When no config path is provided, should return default config
        config = load_config()
        assert isinstance(config, Config)
        assert config.host == "::"  # Updated to match new default

    @pytest.mark.unit
    def test_configure_logging(self, caplog):
        """Test configuring logging from configuration."""
        # Save the original loggers
        original_loggers = logging.Logger.manager.loggerDict.copy()
        original_handlers = logging.root.handlers.copy()

        try:
            # Create a test configuration
            config = Config(
                log_level="DEBUG",
                loggers=[
                    LoggerConfig(name="test.logger", level="INFO"),
                    LoggerConfig(name="test.debug", level="DEBUG", propagate=False),
                ],
            )

            # Configure logging
            configure_logging(config)

            # Check root logger
            assert logging.root.level == logging.DEBUG
            assert len(logging.root.handlers) > 0

            # Check custom loggers
            test_logger = logging.getLogger("test.logger")
            assert test_logger.level == logging.INFO
            assert test_logger.propagate is True

            debug_logger = logging.getLogger("test.debug")
            assert debug_logger.level == logging.DEBUG
            assert debug_logger.propagate is False

        finally:
            # Reset logging configuration
            for handler in logging.root.handlers[:]:
                logging.root.removeHandler(handler)

            # Restore original handlers
            for handler in original_handlers:
                logging.root.addHandler(handler)

            # Clear and restore logger dict
            for logger_name in list(logging.Logger.manager.loggerDict.keys()):
                if logger_name not in original_loggers:
                    del logging.Logger.manager.loggerDict[logger_name]
