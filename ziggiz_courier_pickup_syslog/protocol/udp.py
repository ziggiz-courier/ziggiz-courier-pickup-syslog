# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# UDP Protocol implementation for syslog server

# Standard library imports
import asyncio
import logging

from typing import Optional, Tuple


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """
    UDP Protocol implementation for handling syslog messages.

    This class implements the asyncio DatagramProtocol for receiving
    and handling UDP syslog messages.
    """

    def __init__(self):
        """Initialize the UDP protocol."""
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.protocol.udp")
        self.transport = None

    def connection_made(self, transport) -> None:
        """
        Called when the connection is established.

        Args:
            transport: The transport for the connection
        """
        self.transport = transport
        socket_info = transport.get_extra_info("socket")
        if socket_info:
            host, port = socket_info.getsockname()
            self.logger.info(f"UDP server started on {host}:{port}")
        else:
            self.logger.info("UDP server started")

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        """
        Called when a UDP datagram is received.

        Args:
            data: The datagram data
            addr: The address (host, port) of the sender
        """
        host, port = addr
        self.logger.debug(f"Received UDP datagram from {host}:{port}")

        # Just log the data without parsing
        message = data.decode("utf-8", errors="replace")
        self.logger.info(f"Syslog message from {host}:{port}: {message}")

    def error_received(self, exc: Exception) -> None:
        """
        Called when a previous send or receive operation raises an OSError.

        Args:
            exc: The exception that was raised
        """
        self.logger.error(f"Error in UDP server: {exc}")

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """
        Called when the connection is lost or closed.

        Args:
            exc: The exception that caused the connection to close,
                 or None if the connection was closed without an error
        """
        if exc:
            self.logger.warning(f"UDP server connection closed with error: {exc}")
        else:
            self.logger.info("UDP server connection closed")
