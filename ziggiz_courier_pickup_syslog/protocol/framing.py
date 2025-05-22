# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Framing helper for syslog messages

# Standard library imports
import logging
import re

from enum import Enum
from typing import List, Optional

# Constants
DEFAULT_END_OF_MSG_MARKER = b"\n"
DEFAULT_MAX_MSG_LENGTH = 16 * 1024  # 16 KiB


class FramingMode(Enum):
    """Enumeration for the framing mode."""

    AUTO = "auto"
    TRANSPARENT = "transparent"
    NON_TRANSPARENT = "non_transparent"


class FramingDetectionError(Exception):
    """Exception raised when there's an error in framing detection."""


class FramingHelper:
    """
    Helper class for handling message framing in syslog streams.

    This class helps detect and extract syslog messages from byte streams using
    different framing modes: transparent (octet-counting), non-transparent (delimiter-based),
    or auto-detection between the two.
    """

    def __init__(
        self,
        framing_mode: FramingMode = FramingMode.AUTO,
        end_of_msg_marker: bytes = DEFAULT_END_OF_MSG_MARKER,
        max_msg_length: int = DEFAULT_MAX_MSG_LENGTH,
        logger: Optional[logging.Logger] = None,
    ):
        """
        Initialize the framing helper.

        Args:
            framing_mode: The framing mode to use
            end_of_msg_marker: The marker indicating end of message for non-transparent framing
            max_msg_length: Maximum message length for non-transparent framing
            logger: Logger instance
        """
        self.framing_mode = framing_mode
        self.end_of_msg_marker = end_of_msg_marker
        self.max_msg_length = max_msg_length
        self.logger = logger or logging.getLogger(__name__)
        self._buffer = bytearray()
        self._detected_mode = None if framing_mode == FramingMode.AUTO else framing_mode

        # For performance, pre-calculate end marker length
        self.end_marker_len = len(end_of_msg_marker)

        # Compile regex pattern for transparent framing octet count (optimized version)
        # Pattern matches: [1-9] followed by 0-4 digits, followed by a space
        self._octet_count_pattern = re.compile(b"^([1-9][0-9]{0,4}) ")

    def add_data(self, data: bytes) -> None:
        """
        Add data to the buffer.

        Args:
            data: The data to add to the buffer
        """
        self._buffer.extend(data)

    def extract_messages(self) -> List[bytes]:
        """
        Extract complete messages from the buffer.

        Returns:
            A list of complete messages extracted from the buffer
        """
        if not self._buffer:
            return []

        messages = []

        # Keep extracting messages as long as possible
        while True:
            message = None

            # Extract message based on current mode
            if self.framing_mode == FramingMode.AUTO:
                message = self._extract_auto_mode()
            elif self.framing_mode == FramingMode.TRANSPARENT:
                message = self._extract_transparent_mode()
            elif self.framing_mode == FramingMode.NON_TRANSPARENT:
                message = self._extract_non_transparent_mode()

            if message is not None:
                messages.append(message)
            else:
                # No more complete messages
                break

        return messages

    def _extract_auto_mode(self) -> Optional[bytes]:
        """
        Extract a message using auto-detection mode.

        Returns:
            A complete message if one was extracted, None otherwise
        """
        # Try to detect the framing mode if it hasn't been detected yet
        if self._detected_mode is None:
            self._detect_framing_mode()

        # If we still don't know, we need more data
        if self._detected_mode is None:
            return None

        # Extract using the detected mode
        if self._detected_mode == FramingMode.TRANSPARENT:
            return self._extract_transparent_mode()
        else:
            return self._extract_non_transparent_mode()

    def _detect_framing_mode(self) -> None:
        """
        Detect the framing mode based on the current buffer content.

        Sets _detected_mode to TRANSPARENT or NON_TRANSPARENT if detection is successful.
        """
        # If buffer is too short, we can't detect yet
        if len(self._buffer) < 2:
            return

        # Find the first space
        space_pos = -1
        for i, byte in enumerate(self._buffer):
            if byte == 32:  # ASCII for space
                space_pos = i
                break

        # Check if no space was found or space is at an invalid position
        if space_pos <= 0 or space_pos > 6:  # No space or more than 5 digits
            self._detected_mode = FramingMode.NON_TRANSPARENT
            self.logger.debug("Detected non-transparent (delimiter-based) framing mode")
            return

        # Check that characters before space are valid digits
        # First digit must be 1-9 (ASCII 49-57) - no leading zeros
        if not (48 < self._buffer[0] <= 57):
            self._detected_mode = FramingMode.NON_TRANSPARENT
            self.logger.debug("Detected non-transparent (delimiter-based) framing mode")
            return

        # Verify all other characters before the space are digits
        for i in range(1, space_pos):
            if not (48 <= self._buffer[i] <= 57):  # ASCII for digits 0-9
                self._detected_mode = FramingMode.NON_TRANSPARENT
                self.logger.debug(
                    "Detected non-transparent (delimiter-based) framing mode"
                )
                return

        # If we get here, it looks like a transparent framing format
        self._detected_mode = FramingMode.TRANSPARENT
        self.logger.debug("Detected transparent (octet-counting) framing mode")

    def _extract_transparent_mode(self) -> Optional[bytes]:
        """
        Extract a message using transparent (octet-counting) mode.

        Returns:
            A complete message if one was extracted, None otherwise
        Raises:
            FramingDetectionError: If the frame format is invalid in TRANSPARENT mode
        """
        # If buffer is too small to even contain an octet count and space, wait for more data
        if len(self._buffer) < 2:
            return None

        # Use regex to match the octet count at the beginning of the buffer
        match = self._octet_count_pattern.match(self._buffer)

        # No valid octet count found
        if not match:
            if self.framing_mode == FramingMode.TRANSPARENT:
                raise FramingDetectionError("Invalid transparent framing format")
            return None

        try:
            # Extract the octet count
            octet_count = int(match.group(1))

            # Validate octet count (reasonable limits to prevent exhausting memory)
            if octet_count <= 0 or octet_count > 1048576:  # Max 1MB per message
                if self.framing_mode == FramingMode.TRANSPARENT:
                    raise FramingDetectionError(f"Invalid octet count: {octet_count}")
                return None

            # Calculate message boundaries
            header_length = match.end()  # Position right after the space
            total_length = (
                header_length + octet_count
            )  # Total length including header and message

            # Check if we have enough data for the full message
            if len(self._buffer) < total_length:
                self.logger.debug(
                    f"Partial message: have {len(self._buffer)} bytes, need {total_length} bytes"
                )
                return None  # Wait for more data to arrive

            # Extract the message
            message = bytes(self._buffer[header_length:total_length])

            # Remove the processed message from the buffer
            del self._buffer[:total_length]

            # For AUTO mode, reset detection to allow different formats
            if self.framing_mode == FramingMode.AUTO:
                self._detected_mode = None

            return message

        except ValueError:
            if self.framing_mode == FramingMode.TRANSPARENT:
                raise FramingDetectionError("Invalid octet count")
            return None

    def _extract_non_transparent_mode(self) -> Optional[bytes]:
        """
        Extract a message using non-transparent (delimiter-based) mode.

        Returns:
            A complete message if one was extracted, None otherwise
        """
        # Look for the end marker in the buffer
        marker_pos = -1

        # Search for the end marker in chunks respecting max_msg_length
        for i in range(
            min(len(self._buffer) - self.end_marker_len + 1, self.max_msg_length)
        ):
            if self._buffer[i : i + self.end_marker_len] == self.end_of_msg_marker:
                marker_pos = i
                break

        # If end marker not found but we've reached max message length
        if marker_pos == -1:
            if len(self._buffer) >= self.max_msg_length:
                message = bytes(self._buffer[: self.max_msg_length])
                del self._buffer[: self.max_msg_length]
                self.logger.warning(
                    f"Message truncated at max length ({self.max_msg_length} bytes)"
                )
                return message
            return None

        # Extract the message (without the end marker)
        message = bytes(self._buffer[:marker_pos])

        # Remove message and end marker from buffer
        del self._buffer[: marker_pos + self.end_marker_len]

        # For AUTO mode, reset detection to allow different formats
        if self.framing_mode == FramingMode.AUTO:
            self._detected_mode = None

        return message

    def reset(self) -> None:
        """Reset the buffer and detected mode."""
        self._buffer.clear()
        if self.framing_mode == FramingMode.AUTO:
            self._detected_mode = None

    @property
    def buffer_size(self) -> int:
        """Get the current size of the buffer."""
        return len(self._buffer)

    @staticmethod
    def parse_end_of_msg_marker(marker_str: str) -> bytes:
        """
        Parse a string representation of an end-of-message marker into bytes.

        Handles escape sequences like \\n, \\r, \\t, \\0, and hex sequences (\\x00).

        Args:
            marker_str: String representation of the marker

        Returns:
            Bytes representation of the marker

        Raises:
            ValueError: If the marker string is invalid
        """
        # Special handling for common escape sequences
        if marker_str == "\\n":
            return b"\n"
        elif marker_str == "\\r\\n":
            return b"\r\n"
        elif marker_str == "\\0":
            return b"\0"

        # Handle general case with Python's string literal parsing
        try:
            # Check for clearly invalid markers
            if "{" in marker_str or "}" in marker_str:
                raise ValueError(f"Invalid characters in marker: {marker_str}")

            # Use eval to interpret escape sequences
            # This is safe as we're only handling a single string literal
            marker_bytes: bytes = eval(f'b"{marker_str}"', {"__builtins__": {}})
            return marker_bytes
        except Exception as e:
            raise ValueError(f"Invalid end-of-message marker: {marker_str}") from e
