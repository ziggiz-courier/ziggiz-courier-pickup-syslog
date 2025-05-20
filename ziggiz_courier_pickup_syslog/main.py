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


def run_server() -> None:
    """
    Run the syslog server.
    """
    logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")

    try:
        logger.info("Starting syslog server")
        # Placeholder for server implementation
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

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.log_level)
    logger = logging.getLogger("ziggiz_courier_pickup_syslog.main")

    # Run the server
    try:
        logger.info("Starting Ziggiz Courier Syslog Server")
        run_server()
    except KeyboardInterrupt:
        logger.info("Server shutdown requested by user")
    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
