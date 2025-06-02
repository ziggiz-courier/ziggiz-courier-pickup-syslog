# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# TCP Protocol implementation for syslog server with fixed framing
# Standard library imports
import asyncio

from typing import List, Optional, Tuple

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.base_stream import BaseSyslogBufferedProtocol
from ziggiz_courier_pickup_syslog.protocol.ip_filter import IPFilter


class SyslogTCPProtocol(BaseSyslogBufferedProtocol):
    """
    TCP Protocol implementation for handling syslog messages.
    Inherits shared logic from BaseSyslogBufferedProtocol.
    """

    def __init__(
        self,
        framing_mode: str = "auto",
        end_of_message_marker: str = "\n",
        max_message_length: int = 16 * 1024,
        decoder_type: str = "auto",
        allowed_ips: Optional[List[str]] = None,
        deny_action: str = "drop",
        enable_model_json_output: bool = False,
    ):
        self.allowed_ips = allowed_ips
        self.deny_action = deny_action
        self.ip_filter = IPFilter(allowed_ips)
        self.peername: Optional[Tuple[str, int]] = None
        super().__init__(
            framing_mode=framing_mode,
            end_of_message_marker=end_of_message_marker,
            max_message_length=max_message_length,
            decoder_type=decoder_type,
            enable_model_json_output=enable_model_json_output,
        )

    @property
    def logger_name(self) -> str:
        return "ziggiz_courier_pickup_syslog.protocol.tcp"

    def get_peer_info(self) -> dict:
        if self.peername:
            return {"host": self.peername[0], "port": self.peername[1]}
        return {"host": "unknown", "port": "unknown"}

    @property
    def span_name(self) -> str:
        return "syslog.tcp.message"

    def span_attributes(self, peer_info: dict, msg: bytes) -> dict:
        host, port = self.peername if self.peername else ("unknown", "unknown")
        return {
            "net.transport": "ip_tcp",
            "net.peer.ip": host,
            "net.peer.port": port,
            "message.length": len(msg),
        }

    def on_connection_made(self, transport: asyncio.BaseTransport) -> None:
        host, port = self.peername if self.peername else ("unknown", "unknown")

        # Check if the IP is allowed
        if host != "unknown" and not self.ip_filter.is_allowed(host):
            if self.deny_action == "reject":
                # Send a rejection message before closing
                self.logger.warning(
                    "Rejected TCP connection (not in allowed IPs)",
                    extra={
                        "net.transport": "ip_tcp",
                        "net.peer.ip": host,
                        "net.peer.port": port,
                    },
                )
                # We can't send a proper rejection message in TCP, so just close the connection
                transport.close()
            else:  # "drop"
                self.logger.warning(
                    "Dropped TCP connection (not in allowed IPs)",
                    extra={
                        "net.transport": "ip_tcp",
                        "net.peer.ip": host,
                        "net.peer.port": port,
                    },
                )
                transport.close()
            return

        self.logger.info(
            "TCP connection established",
            extra={
                "net.transport": "ip_tcp",
                "net.peer.ip": host,
                "net.peer.port": port,
            },
        )

    def handle_decoded_message(self, decoded_message: object, peer_info: dict) -> None:
        """
        Handle a decoded syslog message received via TCP.
        In a real implementation, this would process the message further.
        """
        self.logger.info(
            f"Received TCP message: {type(decoded_message).__name__}",
            extra={"peer": peer_info},
        )

        # Future implementations would send this to a message processor,
        # message queue, or other destination
