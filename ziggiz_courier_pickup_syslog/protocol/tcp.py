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

    def get_peer_info(self):
        if self.peername:
            return f"{self.peername[0]}:{self.peername[1]}"
        return "unknown"

    @property
    def span_name(self) -> str:
        return "syslog.tcp.message"

    def span_attributes(self, peer_info, msg) -> dict:
        host, port = self.peername if self.peername else ("unknown", "unknown")
        return {
            "net.transport": "ip_tcp",
            "net.peer.ip": host,
            "net.peer.port": port,
            "message.length": len(msg),
        }

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Called when a connection is made.

        Args:
            transport: The transport for the connection
        """
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
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

    def get_buffer(self, sizehint: int) -> bytearray:
        """
        Get a buffer to read incoming data into.

        Args:
            sizehint: A hint about the maximum size of the data that will be read

        Returns:
            A bytearray to be filled with incoming data
        """
        # If sizehint is negative, use max_buffer_size (asyncio convention)
        if sizehint is None or sizehint < 0:
            buffer_size = self.max_buffer_size
        else:
            buffer_size = min(sizehint, self.max_buffer_size)
        self._read_buffer = bytearray(buffer_size)
        return self._read_buffer

    def eof_received(self) -> bool:
        """
        Called when the other end signals it won't send any more data.

        Returns:
            False to close the transport, True to keep it open
        """
        host, port = self.peername if self.peername else ("unknown", "unknown")
        self.logger.debug("EOF received", extra={"host": host, "port": port})

        # Extract and process any final messages
        try:
            # Get any remaining messages from the framing helper buffer
            messages = self.framing_helper.extract_messages()

            # Process complete messages
            for msg in messages:
                if msg:  # Skip empty messages
                    message = msg.decode("utf-8", errors="replace")

                    try:
                        decoded_message = self.decoder.decode(message)
                        if decoded_message is not None:
                            if self.enable_model_json_output:
                                try:
                                    if hasattr(decoded_message, "model_dump_json"):
                                        model_json = decoded_message.model_dump_json(
                                            indent=2
                                        )
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

                                            model_json = json.dumps(
                                                model_dict, default=str, indent=2
                                            )
                                        else:
                                            model_json = None
                                    else:
                                        model_json = None
                                    if model_json:
                                        self.logger.debug(
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
                                "Final syslog message",
                                extra={
                                    "msg_type": msg_type,
                                    "host": host,
                                    "port": port,
                                    "message": message,
                                },
                            )
                    except ImportError:
                        self.logger.info(
                            "Final syslog message",
                            extra={"host": host, "port": port, "message": message},
                        )
                    except Exception as e:
                        self.logger.warning(
                            "Failed to parse final syslog message",
                            extra={"host": host, "port": port, "error": e},
                        )
                        self.logger.info(
                            "Raw final syslog message",
                            extra={"host": host, "port": port, "message": message},
                        )

            # Check if there's still data in the buffer that couldn't be parsed
            if self.framing_helper.buffer_size > 0:
                self.logger.warning(
                    "Discarding unparsed data",
                    extra={
                        "buffer_size": self.framing_helper.buffer_size,
                        "host": host,
                        "port": port,
                    },
                )
        except Exception as e:
            self.logger.error(
                "Error processing final data",
                extra={"host": host, "port": port, "error": e},
            )

        # Return False to close the transport
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """
        Called when the connection is lost or closed.

        Args:
            exc: The exception that caused the connection to close,
                 or None if the connection was closed without an error
        """
        host, port = self.peername if self.peername else ("unknown", "unknown")

        if exc:
            self.logger.debug(
                "TCP connection closed with error",
                extra={
                    "net.transport": "ip_tcp",
                    "net.peer.ip": host,
                    "net.peer.port": port,
                    "error": exc,
                },
            )
        else:
            self.logger.debug(
                "TCP connection closed",
                extra={
                    "net.transport": "ip_tcp",
                    "net.peer.ip": host,
                    "net.peer.port": port,
                },
            )

        # Reset the framing helper and clear buffers
        self.framing_helper.reset()
        self._read_buffer = None
        self.transport = None
