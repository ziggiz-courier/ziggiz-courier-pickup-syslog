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
from ziggiz_courier_pickup_syslog.protocol.framing import (
    FramingMode,
)


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

    def get_peer_info(self):
        # For Unix sockets, peername is a file path if available
        if self.peername:
            return self.peername
        return "unknown"

    @property
    def span_name(self) -> str:
        return "syslog.unix.message"

    def span_attributes(self, peer_info, msg) -> dict:
        return {
            "net.transport": "unix",
            "peer": peer_info,
            "message.length": len(msg),
        }

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Called when a connection is made.

        Args:
            transport: The transport for the connection
        """
        self.transport = transport
        # For Unix sockets, peername is a file path if available
        self.peername = transport.get_extra_info("peername")

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

    def eof_received(self) -> bool:
        """
        Called when the other end signals it won't send any more data.

        Returns:
            False to close the transport, True to keep it open
        """
        peer_info = self.peername or "unknown"
        self.logger.debug("EOF received", extra={"peer": peer_info})

        # Extract and process any final messages
        try:
            # Store original buffer data for potential processing
            buffer_data = bytes(self.framing_helper._buffer)

            # Get any remaining messages from the framing helper buffer
            messages = self.framing_helper.extract_messages()

            # Process complete messages
            for msg in messages:
                if msg:  # Skip empty messages
                    message = msg.decode("utf-8", errors="replace")

                    try:
                        decoded_message = self.decoder.decode(message)
                        if self.enable_model_json_output:
                            try:
                                model_json = None
                                if decoded_message is not None:
                                    if hasattr(
                                        decoded_message, "model_dump_json"
                                    ) and callable(
                                        getattr(
                                            decoded_message, "model_dump_json", None
                                        )
                                    ):
                                        model_json = decoded_message.model_dump_json(
                                            indent=2
                                        )
                                    elif hasattr(decoded_message, "json") and callable(
                                        getattr(decoded_message, "json", None)
                                    ):
                                        model_json = decoded_message.json(indent=2)
                                    elif hasattr(
                                        decoded_message, "model_dump"
                                    ) and callable(
                                        getattr(decoded_message, "model_dump", None)
                                    ):
                                        model_dict = decoded_message.model_dump()
                                        # Standard library imports
                                        import json

                                        model_json = json.dumps(
                                            model_dict, default=str, indent=2
                                        )
                                    elif hasattr(decoded_message, "dict") and callable(
                                        getattr(decoded_message, "dict", None)
                                    ):
                                        model_dict = decoded_message.dict()
                                        # Standard library imports
                                        import json

                                        model_json = json.dumps(
                                            model_dict, default=str, indent=2
                                        )
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
                            "Final syslog message (%(msg_type)s) from %(peer)s: %(message)s",
                            {
                                "msg_type": msg_type,
                                "peer": peer_info,
                                "message": message,
                            },
                        )
                    except ImportError:
                        self.logger.info(
                            "Final syslog message from %(peer)s: %(message)s",
                            {"peer": peer_info, "message": message},
                        )
                    except Exception as e:
                        self.logger.warning(
                            "Failed to parse final syslog message from %(peer)s: %(error)s",
                            {"peer": peer_info, "error": e},
                        )
                        self.logger.info(
                            "Raw final syslog message from %(peer)s: %(message)s",
                            {"peer": peer_info, "message": message},
                        )

            # Handle remaining data in the buffer based on framing mode
            if not messages and buffer_data:
                # For non-transparent mode or test cases, process the buffer as a message
                if self.framing_helper.framing_mode == FramingMode.NON_TRANSPARENT or (
                    self.framing_helper.framing_mode == FramingMode.AUTO
                    and self.framing_helper._detected_mode != FramingMode.TRANSPARENT
                ):
                    message = buffer_data.decode("utf-8", errors="replace")
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
                                "Final syslog message (%(msg_type)s) from %(peer)s: %(message)s",
                                {
                                    "msg_type": msg_type,
                                    "peer": peer_info,
                                    "message": message,
                                },
                            )
                    except ImportError:
                        self.logger.info(
                            "Final syslog message from %(peer)s: %(message)s",
                            {"peer": peer_info, "message": message},
                        )
                    except Exception as e:
                        self.logger.warning(
                            "Failed to parse final syslog message from %(peer)s: %(error)s",
                            {"peer": peer_info, "error": e},
                        )
                        self.logger.info(
                            "Raw final syslog message from %(peer)s: %(message)s",
                            {"peer": peer_info, "message": message},
                        )
                    self.framing_helper._buffer.clear()
                # For transparent mode with partial data, log a warning
                elif self.framing_helper.framing_mode == FramingMode.TRANSPARENT or (
                    self.framing_helper.framing_mode == FramingMode.AUTO
                    and self.framing_helper._detected_mode == FramingMode.TRANSPARENT
                ):
                    match = self.framing_helper._octet_count_pattern.match(buffer_data)
                    if match:
                        try:
                            octet_count = int(match.group(1))
                            header_length = match.end()
                            received_bytes = len(buffer_data) - header_length
                            self.logger.warning(
                                "Incomplete transparent message from %(peer)s: "
                                "received %(received)d of %(octet)d bytes",
                                {
                                    "peer": peer_info,
                                    "received": received_bytes,
                                    "octet": octet_count,
                                },
                            )
                        except (ValueError, OverflowError) as e:
                            self.logger.error(
                                "Invalid octet count in transparent message from %(peer)s: %(error)s",
                                {"peer": peer_info, "error": e},
                            )
                    elif buffer_data.isascii() and not buffer_data.isdigit():
                        message = buffer_data.decode("utf-8", errors="replace")
                        self.logger.warning(
                            "Received non-transparent data in transparent mode from %(peer)s. "
                            "Data: %(message)s",
                            {"peer": peer_info, "message": message},
                        )
                        try:
                            decoded_message = self.decoder.decode(message)
                            if decoded_message is not None:
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
                                    "Final syslog message (%(msg_type)s) from %(peer)s: %(message)s",
                                    {
                                        "msg_type": msg_type,
                                        "peer": peer_info,
                                        "message": message,
                                    },
                                )
                        except (ImportError, Exception):
                            pass
                        self.framing_helper._buffer.clear()

            # Check if there's still data in the buffer that couldn't be parsed
            if self.framing_helper.buffer_size > 0:
                self.logger.warning(
                    "Discarding %(buffer_size)d bytes of unparsed data from %(peer)s",
                    {"buffer_size": self.framing_helper.buffer_size, "peer": peer_info},
                )
        except Exception as e:
            self.logger.error(
                "Error processing final data from %(peer)s: %(error)s",
                {"peer": peer_info, "error": e},
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
        peer_info = self.peername or "unknown"

        if exc:
            self.logger.warning(
                "Unix Stream connection from %(peer)s closed with error: %(error)s",
                {"peer": peer_info, "error": exc},
            )
        else:
            self.logger.debug(
                "Unix Stream connection from %(peer)s closed", {"peer": peer_info}
            )

        # Reset the framing helper and clear buffers
        self.framing_helper.reset()
        self._read_buffer = None
        self.transport = None
