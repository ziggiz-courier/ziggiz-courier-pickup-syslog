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
import logging

from typing import Optional


class SyslogUnixProtocol(asyncio.BufferedProtocol):
    """
    Unix Stream Protocol implementation for handling syslog messages.

    This class implements the asyncio BufferedProtocol for receiving
    and handling Unix Stream syslog messages efficiently, using lower-level
    buffer operations to minimize data copying.
    """

    def __init__(self):
        """Initialize the Unix Stream protocol."""
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.protocol.unix")
        self.transport = None
        self.peername = None
        # This buffer is used to accumulate message parts across callbacks
        self.buffer = bytearray()
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
        peer_id = self.peername or "unknown"
        self.logger.info(f"Unix Stream connection established from {peer_id}")

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
        peer_id = self.peername or "unknown"
        self.logger.debug(f"Received {nbytes} bytes of Unix Stream data from {peer_id}")

        # Add the received data to our message accumulation buffer
        data = self._read_buffer[:nbytes]
        self.buffer.extend(data)

        # Try to extract complete messages
        # The simplest approach is to split on newline characters
        # which is common in syslog messages
        if b"\n" in self.buffer:
            # Split the buffer on newline
            messages = self.buffer.split(b"\n")

            # Keep the last incomplete message (if any) in the buffer
            self.buffer = bytearray(messages.pop() if messages[-1] else b"")

            # Process complete messages
            for msg in messages:
                if msg:  # Skip empty messages
                    message = msg.decode("utf-8", errors="replace")
                    self.logger.info(f"Syslog message from {peer_id}: {message}")

    def eof_received(self) -> bool:
        """
        Called when the other end signals it won't send any more data.

        Returns:
            False to close the transport, True to keep it open
        """
        peer_id = self.peername or "unknown"
        self.logger.debug(f"EOF received from {peer_id}")

        # If there's any data left in the buffer, process it as a final message
        if self.buffer:
            message = self.buffer.decode("utf-8", errors="replace")
            self.logger.info(f"Final syslog message from {peer_id}: {message}")
            self.buffer.clear()

        # Return False to close the transport
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """
        Called when the connection is lost or closed.

        Args:
            exc: The exception that caused the connection to close,
                 or None if the connection was closed without an error
        """
        peer_id = self.peername or "unknown"

        if exc:
            self.logger.warning(
                f"Unix Stream connection from {peer_id} closed with error: {exc}"
            )
        else:
            self.logger.info(f"Unix Stream connection from {peer_id} closed")

        # Clear the buffers
        self.buffer.clear()
        self._read_buffer = None
        self.transport = None
