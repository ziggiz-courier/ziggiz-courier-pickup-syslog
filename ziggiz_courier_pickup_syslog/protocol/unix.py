# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Unix Stream Protocol implementation for syslog server


# Standard library imports
import asyncio

from typing import Optional

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.base_stream import BaseSyslogBufferedProtocol


class SyslogUnixProtocol(BaseSyslogBufferedProtocol):
    """
    Unix Stream Protocol implementation for handling syslog messages.
    Inherits shared logic from BaseSyslogBufferedProtocol.
    """

    def __init__(
        self,
        framing_mode: str = "auto",
        end_of_message_marker: str = "\n",
        max_message_length: int = 16 * 1024,
        decoder_type: str = "auto",
        enable_model_json_output: bool = False,
    ):
        self.peername: Optional[str] = None
        super().__init__(
            framing_mode=framing_mode,
            end_of_message_marker=end_of_message_marker,
            max_message_length=max_message_length,
            decoder_type=decoder_type,
            enable_model_json_output=enable_model_json_output,
        )

    @property
    def logger_name(self) -> str:
        return "ziggiz_courier_pickup_syslog.protocol.unix"

    def get_peer_info(self) -> dict:
        # For Unix sockets, peername is a file path if available
        if self.peername:
            return {"peer": self.peername}
        return {"peer": "unknown"}

    @property
    def span_name(self) -> str:
        return "syslog.unix.message"

    def span_attributes(self, peer_info: dict, msg: bytes) -> dict:
        return {
            "net.transport": "unix",
            "peer": peer_info,
            "message.length": len(msg),
        }

    def on_connection_made(self, transport: asyncio.BaseTransport) -> None:
        # Use socket peer credentials if available (for Linux)
        peer_creds = transport.get_extra_info("peercreds")

        if peer_creds and isinstance(peer_creds, tuple) and len(peer_creds) == 3:
            pid, uid, gid = peer_creds
            peer_info = f"PID={pid}, UID={uid}, GID={gid}"
        else:
            peer_info = self.peername or "unknown"

        self.logger.debug(
            "Unix Stream connection established", extra={"peer": peer_info}
        )

    def handle_decoded_message(self, decoded_message: object, peer_info: dict) -> None:
        """
        Handle a decoded syslog message received via Unix socket.
        In a real implementation, this would process the message further.
        """
        self.logger.info(
            f"Received Unix message: {type(decoded_message).__name__}",
            extra={"peer": peer_info},
        )

        # Future implementations would send this to a message processor,
        # message queue, or other destination

    # No protocol-specific EOF handling needed; using base implementation.
