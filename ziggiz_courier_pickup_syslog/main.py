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


def setup_logging(log_level: str) -> None:
    """
    Configure logging with appropriate formatters and handlers.

    Args:
        log_level: The logging level to set (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    """
    level = getattr(logging, log_level.upper(), logging.INFO)

    # Create a formatter with timestamp, level, and logger name
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
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


async def start_servers(host: str, udp_port: int, tcp_port: int, loop=None) -> tuple:
    """
    Start the syslog server services (UDP and TCP).

    Args:
        host: The host address to bind to
        udp_port: The port to listen on for UDP
        tcp_port: The port to listen on for TCP
        loop: Optional event loop to use, defaults to current event loop

    Returns:
        A tuple of (udp_transport, udp_protocol, tcp_server)
    """
    logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")

    # Get the event loop if not provided
    if loop is None:
        loop = asyncio.get_event_loop()

    # Setup UDP server
    # Local/package imports
    from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol

    udp_transport, udp_protocol = None, None
    try:
        udp_transport, udp_protocol = await loop.create_datagram_endpoint(
            SyslogUDPProtocol, local_addr=(host, udp_port)
        )
        logger.info(f"UDP server listening on {host}:{udp_port}")
    except Exception as e:
        logger.error(f"Failed to start UDP server: {e}")

    # Setup TCP server
    # Local/package imports
    from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol

    tcp_server = None
    try:
        tcp_server = await loop.create_server(SyslogTCPProtocol, host, tcp_port)
        logger.info(f"TCP server listening on {host}:{tcp_port}")
    except Exception as e:
        logger.error(f"Failed to start TCP server: {e}")

    return udp_transport, udp_protocol, tcp_server


def run_server(host: str = "0.0.0.0", udp_port: int = 514, tcp_port: int = 514) -> None:
    """
    Run the syslog server.

    Args:
        host: The host address to bind to (default: "0.0.0.0")
        udp_port: The port to listen on for UDP (default: 514)
        tcp_port: The port to listen on for TCP (default: 514)
    """
    logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")

    try:
        logger.info(
            f"Starting syslog server on {host}, UDP port {udp_port}, TCP port {tcp_port}"
        )

        # Create and run the event loop
        loop = asyncio.get_event_loop()

        # Start the servers
        udp_transport, udp_protocol, tcp_server = loop.run_until_complete(
            start_servers(host, udp_port, tcp_port)
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
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="0.0.0.0",
        help="Host address to bind to (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--udp-port",
        type=int,
        default=514,
        help="UDP port to listen on (default: 514)",
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=514,
        help="TCP port to listen on (default: 514)",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")

    # Run the server
    try:
        logger.info("Starting Ziggiz Courier Syslog Server")
        run_server(args.host, args.udp_port, args.tcp_port)
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
