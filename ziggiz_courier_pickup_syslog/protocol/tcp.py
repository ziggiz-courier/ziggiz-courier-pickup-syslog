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

from typing import Optional

# Local/package imports
# Local imports
from ziggiz_courier_pickup_syslog.protocol.framing import (
    FramingDetectionError,
    FramingHelper,
    FramingMode,
)


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
    ):
        """
        Initialize the TCP protocol.

        Args:
            framing_mode: The framing mode to use ("auto", "transparent", or "non_transparent")
            end_of_message_marker: The marker indicating end of message for non-transparent framing
            max_message_length: Maximum message length for non-transparent framing
        """
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.protocol.tcp")
        self.transport = None
        self.peername = None

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
            self.logger.error(f"Error setting up framing: {e}")
            # Fall back to default settings
            self.framing_helper = FramingHelper(logger=self.logger)

        # This is the buffer provided by the transport for reading incoming data
        self._read_buffer = None
        # Maximum size to allocate for the incoming buffer
        self.max_buffer_size = 65536  # 64KB

    def connection_made(self, transport) -> None:
        """
        Called when a connection is made.

        Args:
            transport: The transport for the connection
        """
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        host, port = self.peername if self.peername else ("unknown", "unknown")
        self.logger.info(f"TCP connection established from {host}:{port}")

    def get_buffer(self, sizehint: int) -> bytearray:
        """
        Get a buffer to read incoming data into.

        Args:
            sizehint: A hint about the maximum size of the data that will be read

        Returns:
            A bytearray to be filled with incoming data
        """
        # Create a new buffer of the requested size, capped by max_buffer_size
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
        self.logger.debug(f"Received {nbytes} bytes of TCP data from {host}:{port}")

        # Add the received data to the framing helper
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
                    f"Buffer size after adding data: {self.framing_helper.buffer_size} bytes"
                )

            # Extract all complete messages that can be processed
            messages = self.framing_helper.extract_messages()

            # Process complete messages
            for msg in messages:
                if msg:  # Skip empty messages
                    message = msg.decode("utf-8", errors="replace")
                    self.logger.info(f"Syslog message from {host}:{port}: {message}")
        except FramingDetectionError as e:
            self.logger.error(f"Framing error from {host}:{port}: {e}")
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
        self.logger.debug(f"EOF received from {host}:{port}")

        # Extract and process any final messages
        try:
            # Get any remaining messages from the framing helper buffer
            messages = self.framing_helper.extract_messages()

            # Process complete messages
            for msg in messages:
                if msg:  # Skip empty messages
                    message = msg.decode("utf-8", errors="replace")
                    self.logger.info(
                        f"Final syslog message from {host}:{port}: {message}"
                    )

            # Check if there's still data in the buffer that couldn't be parsed
            if self.framing_helper.buffer_size > 0:
                self.logger.warning(
                    f"Discarding {self.framing_helper.buffer_size} bytes of unparsed data from {host}:{port}"
                )
        except Exception as e:
            self.logger.error(f"Error processing final data from {host}:{port}: {e}")

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
                f"TCP connection from {host}:{port} closed with error: {exc}"
            )
        else:
            self.logger.info(f"TCP connection from {host}:{port} closed")

        # Reset the framing helper and clear buffers
        self.framing_helper.reset()
        self._read_buffer = None
        self.transport = None

    # Add an alias for the buffer property to support legacy tests
    @property
    def buffer(self):
        """Compatibility property for accessing the framing helper's buffer."""
        return self.framing_helper._buffer
