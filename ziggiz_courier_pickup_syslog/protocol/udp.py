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
    and handling UDP syslog messages. It supports handling of large datagrams
    that may require IP-level fragmentation and reassembly.
    """

    def __init__(
        self,
        decoder_type: str = "auto",
        allowed_ips: Optional[List[str]] = None,
        deny_action: str = "drop",
        enable_model_json_output: bool = False,
        buffer_size: int = 65536,  # 64KB default buffer size
    ):
        """
        Initialize the UDP protocol.

        Args:
            decoder_type: The type of syslog decoder to use ("auto", "rfc3164", "rfc5424", or "base")
            allowed_ips: List of allowed IP addresses/networks (empty list means allow all)
            deny_action: Action to take for denied connections: "drop" or "reject"
            enable_model_json_output: Whether to generate JSON output of decoded models (for demos/debugging)
            buffer_size: Size of the UDP receive buffer (to accommodate reassembled IP fragments)
        """
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.protocol.udp")
        self.transport: Optional[asyncio.BaseTransport] = None
        self.decoder_type = decoder_type
        self.deny_action = deny_action
        self.enable_model_json_output = enable_model_json_output
        self.buffer_size = buffer_size

        # Initialize IP filter
        self.ip_filter = IPFilter(allowed_ips)

        # Connection-specific cache for the decoder
        self.connection_cache: Dict[Any, Any] = {}
        # Event parsing cache for test compatibility
        self.event_parsing_cache: Dict[Any, Any] = {}
        # Create a decoder instance scoped to this UDP handler
        self.decoder = DecoderFactory.create_decoder(
            self.decoder_type,
            connection_cache=self.connection_cache,
        )

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Called when the connection is established.

        Args:
            transport: The transport for the connection
        """
        self.transport = transport
        socket_info = transport.get_extra_info("socket")
        if socket_info:
            # Configure UDP socket buffer size to handle fragmented packets
            try:
                socket_info.setsockopt(
                    socket_info.SOL_SOCKET, socket_info.SO_RCVBUF, self.buffer_size
                )
                actual_buffer_size = socket_info.getsockopt(
                    socket_info.SOL_SOCKET, socket_info.SO_RCVBUF
                )
                self.logger.debug(
                    "UDP receive buffer size configured",
                    extra={
                        "requested_size": self.buffer_size,
                        "actual_size": actual_buffer_size,
                    },
                )
            except (OSError, AttributeError) as e:
                self.logger.warning(
                    "Failed to set UDP receive buffer size",
                    extra={"error": str(e), "requested_size": self.buffer_size},
                )

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

        try:
            decoded_message = self.decoder.decode(message)
            if self.enable_model_json_output:
                try:
                    if hasattr(decoded_message, "model_dump_json"):
                        model_json = decoded_message.model_dump_json(indent=2)
                    elif hasattr(decoded_message, "json"):
                        model_json = decoded_message.json(indent=2)
                    elif hasattr(decoded_message, "dict") or hasattr(
                        decoded_message, "model_dump"
                    ):
                        dump_method = getattr(
                            decoded_message,
                            "model_dump",
                            getattr(decoded_message, "dict", None),
                        )
                        if dump_method:
                            model_dict = dump_method()
                            # Standard library imports
                            import json

                            model_json = json.dumps(model_dict, default=str, indent=2)
                        else:
                            model_json = None
                    else:
                        model_json = None
                    if model_json:
                        self.logger.info(
                            "Decoded model JSON representation:",
                            extra={"decoded_model_json": model_json},
                        )
                except Exception as json_err:
                    self.logger.warning(
                        "Failed to create JSON representation of decoded model",
                        extra={"error": str(json_err)},
                    )
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
            self.logger.info(
                "Syslog message received",
                extra={"host": host, "port": port, "log_msg": message},
            )
        except Exception as e:
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
