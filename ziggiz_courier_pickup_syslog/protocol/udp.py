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

from typing import Any, Dict, List, Optional, Tuple

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.decoder_factory import DecoderFactory
from ziggiz_courier_pickup_syslog.protocol.ip_filter import IPFilter


class SyslogUDPProtocol(asyncio.DatagramProtocol):
    """
    UDP Protocol implementation for handling syslog messages.

    This class implements the asyncio DatagramProtocol for receiving
    and handling UDP syslog messages.
    """

    def __init__(
        self,
        decoder_type: str = "auto",
        allowed_ips: Optional[List[str]] = None,
        deny_action: str = "drop",
    ):
        """
        Initialize the UDP protocol.

        Args:
            decoder_type: The type of syslog decoder to use ("auto", "rfc3164", "rfc5424", or "base")
            allowed_ips: List of allowed IP addresses/networks (empty list means allow all)
            deny_action: Action to take for denied connections: "drop" or "reject"
        """
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.protocol.udp")
        self.transport = None
        self.decoder_type = decoder_type
        self.deny_action = deny_action

        # Initialize IP filter
        self.ip_filter = IPFilter(allowed_ips)

        # Connection-specific caches for the decoder
        self.connection_cache: Dict[Any, Any] = {}
        self.event_parsing_cache: Dict[Any, Any] = {}

    def connection_made(self, transport) -> None:
        """
        Called when the connection is established.

        Args:
            transport: The transport for the connection
        """
        self.transport = transport
        socket_info = transport.get_extra_info("socket")
        if socket_info:
            sockname = socket_info.getsockname()
            # Handle both IPv4 (host, port) and IPv6 (host, port, flowinfo, scopeid)
            if len(sockname) == 2:
                host, port = sockname
            elif len(sockname) == 4:  # IPv6 address
                host, port, _, _ = sockname
            else:
                host, port = "unknown", "unknown"
            self.logger.info(
                "UDP server started on address", extra={"host": host, "port": port}
            )
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

        # Check if the IP is allowed
        if not self.ip_filter.is_allowed(host):
            if self.deny_action == "reject" and self.transport:
                # For UDP, we can send an ICMP port unreachable message
                self.logger.warning(
                    "Rejected UDP datagram (not in allowed IPs)",
                    extra={"host": host, "port": port},
                )
                # We don't actually send an ICMP message as that would require raw socket access
                # Just log the rejection
            else:  # "drop"
                self.logger.warning(
                    "Dropped UDP datagram (not in allowed IPs)",
                    extra={"host": host, "port": port},
                )
            return

        self.logger.debug("Received UDP datagram", extra={"host": host, "port": port})

        # Decode the data
        message = data.decode("utf-8", errors="replace")

        # Try to use the decoder if ziggiz_courier_handler_core is available
        try:
            decoded_message = DecoderFactory.decode_message(
                self.decoder_type,
                message,
                connection_cache=self.connection_cache,
                event_parsing_cache=self.event_parsing_cache,
            )
            # Log the decoded message with its type
            msg_type = type(decoded_message).__name__
            self.logger.info(
                "Syslog message received",
                extra={
                    "msg_type": msg_type,
                    "host": host,
                    "port": port,
                    "log_msg": message,
                },
            )
        except ImportError:
            # If decoder is not available, just log the raw message
            self.logger.info(
                "Syslog message received",
                extra={"host": host, "port": port, "log_msg": message},
            )
        except Exception as e:
            # Log any parsing errors but don't fail
            self.logger.warning(
                "Failed to parse syslog message",
                extra={"host": host, "port": port, "error": str(e)},
            )
            self.logger.info(
                "Raw syslog message",
                extra={"host": host, "port": port, "log_msg": message},
            )

    def error_received(self, exc: Exception) -> None:
        """
        Called when a previous send or receive operation raises an OSError.

        Args:
            exc: The exception that was raised
        """
        self.logger.error("Error in UDP server", extra={"error": exc})

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """
        Called when the connection is lost or closed.

        Args:
            exc: The exception that caused the connection to close,
                 or None if the connection was closed without an error
        """
        if exc:
            self.logger.warning(
                "UDP server connection closed with error", extra={"error": exc}
            )
        else:
            self.logger.info("UDP server connection closed")
