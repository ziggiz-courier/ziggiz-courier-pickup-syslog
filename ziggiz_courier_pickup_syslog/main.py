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


async def start_server(host: str, port: int, protocol: str, loop=None) -> tuple:
    """
    Start the syslog server service with the specified protocol.

    Args:
        host: The host address to bind to
        port: The port to listen on
        protocol: The protocol to use ("tcp" or "udp")
        loop: Optional event loop to use, defaults to current event loop

    Returns:
        A tuple with the server components based on protocol:
        - For UDP: (transport, protocol_instance, None)
        - For TCP: (None, None, server)
    """
    logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")

    # Get the event loop if not provided
    if loop is None:
        loop = asyncio.get_event_loop()

    udp_transport, udp_protocol, tcp_server = None, None, None

    if protocol.lower() == "udp":
        # Setup UDP server
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol

        try:
            udp_transport, udp_protocol = await loop.create_datagram_endpoint(
                SyslogUDPProtocol, local_addr=(host, port)
            )
            logger.info(f"UDP server listening on {host}:{port}")
        except Exception as e:
            logger.error(f"Failed to start UDP server: {e}")
    elif protocol.lower() == "tcp":
        # Setup TCP server
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol

        try:
            tcp_server = await loop.create_server(SyslogTCPProtocol, host, port)
            logger.info(f"TCP server listening on {host}:{port}")
        except Exception as e:
            logger.error(f"Failed to start TCP server: {e}")
    else:
        logger.error(f"Invalid protocol specified: {protocol}")

    return udp_transport, udp_protocol, tcp_server


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
        logger.info(
            f"Starting syslog server on {host} using {protocol.upper()} protocol on port {port}"
        )

        # Create and run the event loop
        loop = asyncio.get_event_loop()

        # Start the server
        udp_transport, udp_protocol, tcp_server = loop.run_until_complete(
            start_server(host, port, protocol)
        )

        # Run the event loop until interrupted
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            logger.info("Received keyboard interrupt, shutting down...")
        finally:
            # Clean shutdown of servers
            if udp_transport:
                udp_transport.close()
            if tcp_server:
                tcp_server.close()
                loop.run_until_complete(tcp_server.wait_closed())

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
        choices=["tcp", "udp"],
        help="Protocol to use (tcp or udp, overrides config file)",
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
