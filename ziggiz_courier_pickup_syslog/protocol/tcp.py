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
import logging

from typing import Any, Dict, List, Optional, Tuple

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.decoder_factory import DecoderFactory

# Local imports
from ziggiz_courier_pickup_syslog.protocol.framing import (
    FramingDetectionError,
    FramingHelper,
    FramingMode,
)
from ziggiz_courier_pickup_syslog.protocol.ip_filter import IPFilter

# OpenTelemetry import
from ziggiz_courier_pickup_syslog.telemetry import get_tracer


class SyslogTCPProtocol(asyncio.BufferedProtocol):
    """
    TCP Protocol implementation for handling syslog messages.

    This class implements the asyncio BufferedProtocol for receiving
    and handling TCP syslog messages efficiently, using lower-level
    buffer operations to minimize data copying.
    """

    def __init__(
        self,
        framing_mode: str = "auto",
        end_of_message_marker: str = "\\n",
        max_message_length: int = 16 * 1024,
        decoder_type: str = "auto",
        allowed_ips: Optional[List[str]] = None,
        deny_action: str = "drop",
        enable_model_json_output: bool = False,
    ):
        """
        Initialize the TCP protocol.

        Args:
            framing_mode: The framing mode to use ("auto", "transparent", or "non_transparent")
            end_of_message_marker: The marker indicating end of message for non-transparent framing
            max_message_length: Maximum message length for non-transparent framing
            decoder_type: The type of syslog decoder to use ("auto", "rfc3164", "rfc5424", or "base")
            allowed_ips: List of allowed IP addresses/networks (empty list means allow all)
            deny_action: Action to take for denied connections: "drop" or "reject"
            enable_model_json_output: Whether to generate JSON output of decoded models (for demos/debugging)
        """
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.protocol.tcp")
        self.transport: Optional[asyncio.BaseTransport] = None
        self.peername: Optional[Tuple[str, int]] = None
        self.decoder_type = decoder_type
        self.deny_action = deny_action
        self.enable_model_json_output = enable_model_json_output

        # Initialize IP filter
        self.ip_filter = IPFilter(allowed_ips)

        # Connection-specific cache for the decoder
        self.connection_cache: Dict[Any, Any] = {}
        # Event parsing cache for test compatibility
        self.event_parsing_cache: Dict[Any, Any] = {}
        # Create a decoder instance scoped to this connection
        self.decoder = DecoderFactory.create_decoder(
            self.decoder_type,
            connection_cache=self.connection_cache,
        )

        # Create the framing helper
        try:
            # Convert string framing mode to enum
            framing_enum = FramingMode(framing_mode)
            # Parse the end of message marker
            end_marker_bytes = FramingHelper.parse_end_of_msg_marker(
                end_of_message_marker
            )

            self.framing_helper = FramingHelper(
                framing_mode=framing_enum,
                end_of_msg_marker=end_marker_bytes,
                max_msg_length=max_message_length,
                logger=self.logger,
            )
        except (ValueError, FramingDetectionError) as e:
            self.logger.error("Error setting up framing", extra={"error": e})
            # Fall back to default settings
            self.framing_helper = FramingHelper(logger=self.logger)

        # This is the buffer provided by the transport for reading incoming data
        self._read_buffer: Optional[bytearray] = None
        # Maximum size to allocate for the incoming buffer
        self.max_buffer_size = 65536  # 64KB

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
                    extra={"host": host, "port": port},
                )
                # We can't send a proper rejection message in TCP, so just close the connection
                transport.close()
            else:  # "drop"
                self.logger.warning(
                    "Dropped TCP connection (not in allowed IPs)",
                    extra={"host": host, "port": port},
                )
                transport.close()
            return

        self.logger.info(
            "TCP connection established", extra={"host": host, "port": port}
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

    def buffer_updated(self, nbytes: int) -> None:
        """
        Called when the buffer has been updated with new data.

        Args:
            nbytes: The number of bytes of data in the buffer
        """
        host, port = self.peername if self.peername else ("unknown", "unknown")
        self.logger.debug(
            "Received TCP data", extra={"nbytes": nbytes, "host": host, "port": port}
        )

        # Add the received data to the framing helper
        if self._read_buffer is None:
            self.logger.error("Buffer is None in buffer_updated")
            return
        data = self._read_buffer[:nbytes]
        try:
            # Add data to the helper and extract messages
            self.framing_helper.add_data(data)

            # For transparent mode, log buffer state for debugging
            if self.framing_helper.framing_mode == FramingMode.TRANSPARENT or (
                self.framing_helper.framing_mode == FramingMode.AUTO
                and self.framing_helper._detected_mode == FramingMode.TRANSPARENT
            ):
                self.logger.debug(
                    "Buffer size after adding data",
                    extra={"buffer_size": self.framing_helper.buffer_size},
                )

            # Extract all complete messages that can be processed
            messages = self.framing_helper.extract_messages()

            tracer = get_tracer()
            for msg in messages:
                if msg:  # Skip empty messages
                    message = msg.decode("utf-8", errors="replace")
                    # Start a span for each message, attach connection info as attributes
                    # Third-party imports
                    from opentelemetry.trace import SpanKind

                    with tracer.start_as_current_span(
                        "syslog.tcp.message",
                        kind=SpanKind.SERVER,
                        attributes={
                            "net.transport": "ip_tcp",
                            "net.peer.ip": host,
                            "net.peer.port": port,
                            "message.length": len(msg),
                        },
                    ):
                        try:
                            decoded_message = self.decoder.decode(message)
                            if decoded_message is not None:
                                # Optionally log JSON output if enabled
                                if self.enable_model_json_output:
                                    try:
                                        if hasattr(decoded_message, "model_dump_json"):
                                            model_json = (
                                                decoded_message.model_dump_json(
                                                    indent=2
                                                )
                                            )
                                        elif hasattr(decoded_message, "json"):
                                            model_json = decoded_message.json(indent=2)
                                        elif hasattr(
                                            decoded_message, "dict"
                                        ) or hasattr(decoded_message, "model_dump"):
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
                                            self.logger.info(
                                                "Decoded model JSON representation:",
                                                extra={
                                                    "decoded_model_json": model_json
                                                },
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
        except FramingDetectionError as e:
            self.logger.error(
                "Framing error", extra={"host": host, "port": port, "error": e}
            )
            # If in transparent mode and detection fails, close the connection
            if self.framing_helper.framing_mode == FramingMode.TRANSPARENT:
                self.logger.warning("Closing connection due to framing error")
                if self.transport:
                    self.transport.close()

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
            self.logger.warning(
                "TCP connection closed with error",
                extra={"host": host, "port": port, "error": exc},
            )
        else:
            self.logger.info(
                "TCP connection closed", extra={"host": host, "port": port}
            )

        # Reset the framing helper and clear buffers
        self.framing_helper.reset()
        self._read_buffer = None
        self.transport = None

    # Add an alias for the buffer property to support legacy tests
    @property
    def buffer(self) -> bytes:
        """Compatibility property for accessing the framing helper's buffer."""
        return self.framing_helper._buffer
