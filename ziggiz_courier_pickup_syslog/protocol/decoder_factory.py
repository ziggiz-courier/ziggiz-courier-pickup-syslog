# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Decoder factory for creating syslog message decoders
#
# This module provides a factory class for creating and using syslog message decoders from
# the ziggiz_courier_handler_core package. It supports multiple decoder types:
#   - auto: Uses UnknownSyslogDecoder that tries all formats
#   - rfc3164: Uses SyslogRFC3164Decoder for RFC 3164 formatted messages
#   - rfc5424: Uses SyslogRFC5424Decoder for RFC 5424 formatted messages
#   - base: Uses SyslogRFCBaseDecoder for basic syslog parsing
#
# Each decoder instance is scoped to a specific connection to ensure thread-safety.

# Standard library imports
import json
import logging

from typing import Any, Dict, Optional, Union

# Third-party imports
from ziggiz_courier_handler_core.decoders import (  # type: ignore
    SyslogRFC3164Decoder,
    SyslogRFC5424Decoder,
    SyslogRFCBaseDecoder,
    UnknownSyslogDecoder,
)


class DecoderFactory:
    """
    Factory class for creating syslog message decoders.

    This class provides a centralized way to create and use the various syslog decoder types
    available in the ziggiz_courier_handler_core package:

    - auto: Uses UnknownSyslogDecoder that tries all formats (default)
    - rfc3164: Uses SyslogRFC3164Decoder for RFC 3164 formatted messages (BSD format)
    - rfc5424: Uses SyslogRFC5424Decoder for RFC 5424 formatted messages (newer format with structured data)
    - base: Uses SyslogRFCBaseDecoder for basic syslog parsing

    Each decoder is instantiated per-connection to ensure thread safety, as they maintain
    connection-specific caches.
    """

    # Custom formatter to show extra dictionary in logs
    class ExtraInfoFormatter(logging.Formatter):
        """
        Custom logging formatter that appends extra (non-standard) attributes to the log message as JSON.
        Useful for debugging and structured logging.
        """

        def format(self, record: logging.LogRecord) -> str:
            formatted_message = super().format(record)

            # Extract all non-standard attributes as extra data
            standard_attrs = {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "lineno",
                "funcName",
                "created",
                "asctime",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
            }

            # Collect extra attributes
            extra_dict = {
                key: getattr(record, key)
                for key in record.__dict__
                if key not in standard_attrs and not key.startswith("_")
            }

            if extra_dict:
                extra_str = json.dumps(
                    extra_dict, default=str, sort_keys=True, indent=2
                )
                return f"{formatted_message} - Extra: {extra_str}"
            return formatted_message
            return formatted_message

    # Set up the logger with custom formatter
    logger = logging.getLogger("ziggiz_courier_pickup_syslog.protocol.decoder_factory")

    # Ensure we get all logger messages including debug level
    logger.setLevel(logging.DEBUG)

    # Force propagation to be False so we don't duplicate messages
    logger.propagate = False

    # Create a new handler for this logger
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # Set our custom formatter that displays the extra dictionary
    console_handler.setFormatter(
        ExtraInfoFormatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    # Clear any existing handlers and add our custom one
    if logger.handlers:
        logger.handlers.clear()
    logger.addHandler(console_handler)

    @staticmethod
    def create_decoder(
        decoder_type: str = "auto",
        connection_cache: Optional[Dict[str, Any]] = None,
        event_parsing_cache: Optional[Dict[str, Any]] = None,
    ) -> Union[
        UnknownSyslogDecoder,
        SyslogRFC3164Decoder,
        SyslogRFC5424Decoder,
        SyslogRFCBaseDecoder,
    ]:
        """
        Create a decoder instance based on the specified decoder type.

        The decoder instances are used to parse syslog messages into structured data objects.
        Each decoder type is optimized for different syslog message formats:

        - auto: Uses UnknownSyslogDecoder that tries all formats and is the most flexible
          but less efficient when processing a large number of messages
        - rfc3164: Uses SyslogRFC3164Decoder for BSD-style syslog messages (RFC 3164)
          Format: <PRI>MMM DD HH:MM:SS HOST APP[PID]: MSG
        - rfc5424: Uses SyslogRFC5424Decoder for modern syslog messages (RFC 5424)
          Format: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID [STRUCTURED-DATA] MSG
        - base: Uses SyslogRFCBaseDecoder for basic syslog parsing (minimal validation)

        Connection-specific caches are used to optimize processing and maintain state
        between messages from the same connection, which is important for protocols
        like TCP and Unix sockets.

        Args:
            decoder_type: The type of decoder to create ("auto", "rfc3164", "rfc5424", or "base")
            connection_cache: Optional dictionary for caching connection details
            event_parsing_cache: Optional dictionary for caching event parsing results

        Returns:
            A decoder instance that matches the specified type

        Raises:
            ImportError: If ziggiz_courier_handler_core is not available
            ValueError: If an invalid decoder type is specified
        """

        # Ensure caches are dictionaries, not None
        conn_cache = connection_cache if connection_cache is not None else {}
        event_cache = event_parsing_cache if event_parsing_cache is not None else {}
        decoder_type = decoder_type.lower()

        extra = {
            "decoder_type": decoder_type,
            "has_connection_cache": connection_cache is not None,
            "has_event_parsing_cache": event_parsing_cache is not None,
        }

        DecoderFactory.logger.debug("Creating decoder instance", extra=extra)

        if decoder_type == "auto":
            decoder = UnknownSyslogDecoder(
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
            DecoderFactory.logger.debug(
                "Created UnknownSyslogDecoder instance", extra=extra
            )
            return decoder
        elif decoder_type == "rfc3164":
            decoder = SyslogRFC3164Decoder(
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
            DecoderFactory.logger.debug(
                "Created SyslogRFC3164Decoder instance", extra=extra
            )
            return decoder
        elif decoder_type == "rfc5424":
            decoder = SyslogRFC5424Decoder(
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
            DecoderFactory.logger.debug(
                "Created SyslogRFC5424Decoder instance", extra=extra
            )
            return decoder
        elif decoder_type == "base":
            decoder = SyslogRFCBaseDecoder(
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
            DecoderFactory.logger.debug(
                "Created SyslogRFCBaseDecoder instance", extra=extra
            )
            return decoder
        else:
            DecoderFactory.logger.error(
                "Invalid decoder type specified",
                extra={"decoder_type": decoder_type, "error": "invalid_type"},
            )
            raise ValueError(
                f"Invalid decoder type: {decoder_type}. "
                "Must be one of: auto, rfc3164, rfc5424, base"
            )

    @staticmethod
    def decode_message(
        decoder_type: str,
        message: str,
        connection_cache: Optional[Dict[str, Any]] = None,
        event_parsing_cache: Optional[Dict[str, Any]] = None,
        enable_model_json_output: bool = False,
    ) -> Any:  # Actual return type depends on decoder implementation
        """
        Decode a syslog message using the specified decoder type.

        This method creates the appropriate decoder based on decoder_type and uses it
        to parse the syslog message. The parsed result will be an EventEnvelopeBaseModel
        instance with standardized fields that can be used for further processing.

        Performance considerations:
        - For known message formats, specify the exact decoder type for better performance
        - For mixed message formats, use "auto" but be aware it's less efficient
        - Connection-specific caches improve performance for repeated connections

        Thread safety:
        - Always use connection-specific caches for each unique connection
        - Do not share decoder instances between concurrent connections

        Example decoders for different message formats:
        - RFC3164 (BSD syslog): <34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8
        - RFC5424 (modern syslog): <165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% Message

        Args:
            decoder_type: The type of decoder to use ("auto", "rfc3164", "rfc5424", or "base")
            message: The syslog message to decode
            connection_cache: Optional dictionary for caching connection details
            event_parsing_cache: Optional dictionary for caching event parsing results
            enable_model_json_output: Whether to generate JSON output of decoded models (for demos/debugging)

        Returns:
            The decoded message (an EventEnvelopeBaseModel instance if ziggiz_courier_handler_core is available)

        Raises:
            ImportError: If ziggiz_courier_handler_core is not available
            ValueError: If an invalid decoder type is specified
        """
        # Ensure event_parsing_cache is a dictionary, not None
        event_cache = event_parsing_cache if event_parsing_cache is not None else {}
        conn_cache = connection_cache if connection_cache is not None else {}

        # Create structured logging context
        extra = {
            "decoder_type": decoder_type,
            "message_length": len(message) if message else 0,
            "has_connection_cache": connection_cache is not None,
            "has_event_parsing_cache": event_parsing_cache is not None,
        }

        DecoderFactory.logger.debug("Decoding syslog message", extra=extra)

        try:
            decoder = DecoderFactory.create_decoder(
                decoder_type,
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
            result = decoder.decode(message)

            # Convert the decoded model to a JSON string for demonstration purposes
            # Only do this when explicitly enabled (typically in demo mode)
            if enable_model_json_output:
                try:
                    # Different models might have different serialization methods
                    if hasattr(result, "model_dump_json"):  # Pydantic v2 style
                        model_json = result.model_dump_json(indent=2)
                    elif hasattr(result, "json"):  # Pydantic v1 style
                        model_json = result.json(indent=2)
                    elif hasattr(result, "dict") or hasattr(
                        result, "model_dump"
                    ):  # Dict conversion fallback
                        dump_method = getattr(
                            result, "model_dump", getattr(result, "dict", None)
                        )
                        if dump_method:
                            model_dict = dump_method()
                            model_json = json.dumps(model_dict, default=str, indent=2)
                        else:
                            model_json = json.dumps(
                                {
                                    "info": "Model doesn't support direct JSON serialization"
                                }
                            )
                    else:
                        # Last resort: attempt direct serialization with default converter for custom types
                        model_json = json.dumps(
                            result,
                            default=lambda o: f"<non-serializable: {type(o).__name__}>",
                            indent=2,
                        )

                    # Log the JSON representation of the decoded model
                    DecoderFactory.logger.info(
                        "Decoded model JSON representation:",
                        extra={"decoded_model_json": model_json},
                    )
                except Exception as json_err:
                    DecoderFactory.logger.warning(
                        "Failed to create JSON representation of decoded model",
                        extra={"error": str(json_err)},
                    )

            # Log successful decoding with additional context
            DecoderFactory.logger.debug(
                "Successfully decoded syslog message",
                extra={**extra, "decode_success": True},
            )
            return result
        except Exception as e:
            # Log failed decoding with error details
            DecoderFactory.logger.error(
                "Failed to decode syslog message",
                extra={**extra, "decode_success": False, "error": str(e)},
            )
            raise
