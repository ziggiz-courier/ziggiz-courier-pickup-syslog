# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Configuration module for loading and parsing configuration files

# Standard library imports
import logging

from pathlib import Path
from typing import List, Optional, Union

# Third-party imports
import yaml

from pydantic import BaseModel, Field, field_validator, model_validator


class LoggerConfig(BaseModel):
    """
    Configuration for individual loggers.

    Attributes:
        name (str): Logger name.
        level (str): Logging level (default: "INFO").
        propagate (bool): Whether to propagate logs to parent (default: True).
    """

    name: str
    level: str = "INFO"
    propagate: bool = True


class CertificateRuleConfig(BaseModel):
    """
    Configuration for a certificate verification rule.

    Attributes:
        attribute (str): The certificate attribute to check (e.g., "CN", "OU").
        pattern (str): The regex pattern to match against the attribute value.
        required (bool): Whether this attribute is required to be present (default: True).
    """

    attribute: str
    pattern: str
    required: bool = True


class Config(BaseModel):
    """
    Main configuration class for the Ziggiz Courier Pickup Syslog server.

    This class defines all configuration options for the syslog server, including
    server settings, logging, decoder options, and certificate rules.
    """

    # Server configuration
    host: str = "::"  # IPv6 for dual-stack support
    protocol: str = "tcp"  # "tcp", "udp", "unix", or "tls"
    port: int = 514
    unix_socket_path: Optional[str] = (
        None  # Path for Unix socket when protocol is "unix"
    )
    udp_buffer_size: int = 65536  # UDP receive buffer size (64KB default)

    # IP filtering configuration
    allowed_ips: List[str] = Field(
        default_factory=list  # List of allowed IP addresses/networks (empty list means allow all)
    )
    deny_action: str = (
        "drop"  # Action to take for denied connections: "drop" or "reject"
    )

    # TLS configuration
    tls_certfile: Optional[str] = None  # Path to the server certificate file
    tls_keyfile: Optional[str] = None  # Path to the server private key file
    tls_ca_certs: Optional[str] = (
        None  # Path to the CA certificates file for client verification
    )
    tls_verify_client: bool = False  # Whether to verify client certificates
    tls_min_version: str = "TLSv1_3"  # Minimum TLS version to accept
    tls_ciphers: Optional[str] = (
        None  # Optional cipher string to restrict allowed ciphers
    )
    tls_cert_rules: List[CertificateRuleConfig] = Field(
        default_factory=list  # Rules for verifying client certificate attributes
    )

    # Framing configuration
    framing_mode: str = "auto"  # "auto", "transparent", or "non_transparent"
    end_of_message_marker: str = (
        "\\n"  # End of message marker for non-transparent framing
    )
    max_message_length: int = (
        16 * 1024
    )  # Maximum message length in bytes for non-transparent framing

    # Syslog decoder configuration
    decoder_type: str = "auto"  # "auto", "rfc3164", "rfc5424", or "base"
    enable_model_json_output: bool = (
        False  # Whether to generate JSON output of decoded models (for demos/debugging)
    )

    # Logging configuration
    log_level: str = "INFO"
    log_format: str = "%(asctime)s %(levelname)s %(name)s %(message)s"
    log_date_format: str = "%Y-%m-%d %H:%M:%S"
    loggers: List[LoggerConfig] = Field(default_factory=list)

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate that the log level is a valid Python logging level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        v = v.upper()
        if v not in valid_levels:
            raise ValueError(f"Invalid log level: {v}. Must be one of {valid_levels}")
        return v

    @field_validator("protocol")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        """Validate that the protocol is either TCP, UDP, Unix, or TLS."""
        valid_protocols = ["tcp", "udp", "unix", "tls"]
        v = v.lower()
        if v not in valid_protocols:
            raise ValueError(f"Invalid protocol: {v}. Must be one of {valid_protocols}")
        return v

    @field_validator("framing_mode")
    @classmethod
    def validate_framing_mode(cls, v: str) -> str:
        """Validate that the framing mode is valid."""
        valid_modes = ["auto", "transparent", "non_transparent"]
        v = v.lower()
        if v not in valid_modes:
            raise ValueError(f"Invalid framing mode: {v}. Must be one of {valid_modes}")
        return v

    @field_validator("decoder_type")
    @classmethod
    def validate_decoder_type(cls, v: str) -> str:
        """Validate that the decoder type is valid."""
        valid_types = ["auto", "rfc3164", "rfc5424", "base"]
        v = v.lower()
        if v not in valid_types:
            raise ValueError(f"Invalid decoder type: {v}. Must be one of {valid_types}")
        return v

    @field_validator("tls_min_version")
    @classmethod
    def validate_tls_min_version(cls, v: str) -> str:
        """Validate that the TLS version is valid."""
        valid_versions = ["TLSv1_2", "TLSv1_3"]
        if v.upper() not in [ver.upper() for ver in valid_versions]:
            raise ValueError(
                f"Invalid TLS version: {v}. Must be one of {valid_versions}"
            )
        # Return the original case to match the expected format
        for ver in valid_versions:
            if v.upper() == ver.upper():
                return ver
        return v  # This should never be reached

    @field_validator("deny_action")
    @classmethod
    def validate_deny_action(cls, v: str) -> str:
        """Validate that the deny action is valid."""
        valid_actions = ["drop", "reject"]
        v = v.lower()
        if v not in valid_actions:
            raise ValueError(
                f"Invalid deny action: {v}. Must be one of {valid_actions}"
            )
        return v

    @model_validator(mode="after")
    def validate_tls_cert_rules(self) -> "Config":
        """Validate that certificate rules are only used with client verification."""
        if self.tls_cert_rules and not self.tls_verify_client:
            raise ValueError(
                "Certificate rules can only be used when client verification is enabled "
                "(tls_verify_client must be True)"
            )
        return self


def load_config(config_path: Optional[Union[str, Path]] = None) -> Config:
    """
    Load configuration from a YAML file.

    Args:
        config_path: Path to the configuration file. If None, will look for config.yaml
                   in the current directory and default directories.

    Returns:
        A Config object containing the loaded configuration.

    Raises:
        FileNotFoundError: If the configuration file cannot be found.
        yaml.YAMLError: If the configuration file contains invalid YAML.
    """
    # Default search paths
    search_paths = [
        Path.cwd() / "config.yaml",
        Path.cwd() / "config.yml",
        Path.cwd() / "examples" / "config_basic.yaml",
        Path("/etc/ziggiz-courier-pickup-syslog/config.yaml"),
        Path("/etc/ziggiz-courier-pickup-syslog/config.yml"),
    ]

    # If config path is provided, try that first
    if config_path:
        config_file = Path(config_path)
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
    else:
        # Try default paths
        for path in search_paths:
            if path.exists():
                config_file = path
                break
        else:
            # No config file found, return default configuration
            logging.warning("No configuration file found, using default configuration")
            return Config()

    # Load YAML configuration
    with open(config_file, "r") as f:
        try:
            config_data = yaml.safe_load(f)
            return Config(**config_data)
        except yaml.YAMLError as e:
            logging.error("Error parsing configuration file", extra={"error": e})
            raise
        except Exception as e:
            logging.error("Error loading configuration", extra={"error": e})
            raise


class SafeExtraFormatter(logging.Formatter):
    """
    Custom formatter that substitutes missing extra fields with a blank string.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Add any expected extra fields with blank default if missing
        if not hasattr(record, "decoded_model_json"):
            record.decoded_model_json = ""
        return super().format(record)


def configure_logging(config: "Config") -> None:
    """
    Configure logging based on the provided configuration.

    Args:
        config: The loaded configuration object.
    """
    # Reset logging configuration
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)

    # Configure root logger
    level = getattr(logging, config.log_level, logging.INFO)
    formatter = SafeExtraFormatter(config.log_format, datefmt=config.log_date_format)

    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logging.root.setLevel(level)
    logging.root.addHandler(console_handler)

    # Configure additional loggers from config
    for logger_config in config.loggers:
        logger = logging.getLogger(logger_config.name)
        logger.setLevel(getattr(logging, logger_config.level, logging.INFO))
        logger.propagate = logger_config.propagate
