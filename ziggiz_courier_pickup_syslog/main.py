# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Main entry point for the syslog server

# Standard library imports
import argparse
import asyncio
import logging
import sys

from typing import Optional

# Local/package imports
from ziggiz_courier_pickup_syslog.config import Config, configure_logging, load_config


def setup_logging(log_level: str = "INFO", config: Optional[Config] = None) -> None:
    """
    Configure logging with appropriate formatters and handlers.

    Args:
        log_level: The logging level to set (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        config: Optional configuration object to use for logging setup
    """
    if config:
        # Use the configuration-based logging setup
        configure_logging(config)
    else:
        # Legacy logging setup for backward compatibility
        level = getattr(logging, log_level.upper(), logging.INFO)

        # Create a formatter with timestamp, level, and logger name
        formatter = logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # Configure the root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(level)

        # Add console handler
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

        # Set specific log levels for third-party libraries
        logging.getLogger("aiokafka").setLevel(logging.WARNING)


# Note: The start_server function has been replaced by the SyslogServer class in server.py


def run_server(
    host: str = "::",
    port: int = 514,
    protocol: str = "tcp",
    config: Optional[Config] = None,
) -> None:
    """
    Run the syslog server.

    Args:
        host: The host address to bind to (default: "::")
        port: The port to listen on (default: 514)
        protocol: The protocol to use ("tcp" or "udp", default: "tcp")
        config: Optional configuration object for advanced settings
    """
    logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")

    try:
        # Create a configuration object if not provided
        if not config:
            config = Config(host=host, port=port, protocol=protocol)

        # Create and run the event loop
        loop = asyncio.get_event_loop()

        # Import the SyslogServer class
        # Local/package imports
        from ziggiz_courier_pickup_syslog.server import SyslogServer

        # Create the server instance
        server = SyslogServer(config)

        # Run the server
        try:
            # Start the server
            loop.run_until_complete(server.start(loop))

            # Run the event loop until interrupted
            loop.run_forever()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
        finally:
            # Clean shutdown of server
            loop.run_until_complete(server.stop())

            # Close the event loop
            loop.close()

    except Exception as e:
        logger.exception(f"Failed to run server: {e}")
        sys.exit(1)


def main() -> None:
    """
    Main entry point for the syslog server.
    Parses command-line arguments, sets up logging, and starts the server.
    """
    parser = argparse.ArgumentParser(description="Ziggiz Courier Syslog Server")
    parser.add_argument(
        "--config",
        type=str,
        help="Path to configuration file",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (overrides config file)",
    )
    parser.add_argument(
        "--host",
        type=str,
        help="Host address to bind to (overrides config file)",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="Port to listen on (overrides config file)",
    )
    parser.add_argument(
        "--protocol",
        type=str,
        choices=["tcp", "udp", "unix"],
        help="Protocol to use (tcp, udp, or unix, overrides config file)",
    )
    parser.add_argument(
        "--unix-socket-path",
        type=str,
        help="Path for Unix domain socket (when protocol is unix, overrides config file)",
    )
    parser.add_argument(
        "--framing-mode",
        type=str,
        choices=["auto", "transparent", "non_transparent"],
        help="Framing mode (auto, transparent, or non_transparent, overrides config file)",
    )
    parser.add_argument(
        "--end-of-message-marker",
        type=str,
        help="End of message marker for non-transparent framing (overrides config file)",
    )
    parser.add_argument(
        "--max-message-length",
        type=int,
        help="Maximum message length in bytes for non-transparent framing (overrides config file)",
    )
    parser.add_argument(
        "--decoder-type",
        type=str,
        choices=["auto", "rfc3164", "rfc5424", "base"],
        help="Syslog decoder type (auto, rfc3164, rfc5424, or base, overrides config file)",
    )

    args = parser.parse_args()

    # Load configuration
    try:
        config = load_config(args.config if args.config else None)

        # Override config with command line arguments if provided
        if args.log_level:
            config.log_level = args.log_level
        if args.host:
            config.host = args.host
        if args.port:
            config.port = args.port
        if args.protocol:
            config.protocol = args.protocol
        if args.unix_socket_path:
            config.unix_socket_path = args.unix_socket_path
        if args.framing_mode:
            config.framing_mode = args.framing_mode
        if args.end_of_message_marker:
            config.end_of_message_marker = args.end_of_message_marker
        if args.max_message_length:
            config.max_message_length = args.max_message_length
        if args.decoder_type:
            config.decoder_type = args.decoder_type

        # Setup logging based on configuration
        setup_logging(config=config)
        logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")

        # Log configuration source
        if args.config:
            logger.info(f"Loaded configuration from {args.config}")
        else:
            logger.info("Using default or automatically detected configuration")

        # Run the server
        logger.info("Starting Ziggiz Courier Syslog Server")
        run_server(config.host, config.port, config.protocol, config)
    except KeyboardInterrupt:
        logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")
        logger.info("Server shutdown requested by user")
    except Exception as e:
        # Setup basic logging if we couldn't load the configuration
        if not logging.root.handlers:
            setup_logging("ERROR")
        logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
