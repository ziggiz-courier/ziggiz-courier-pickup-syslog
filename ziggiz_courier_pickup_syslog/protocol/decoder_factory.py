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
from typing import Dict, Optional

# Third-party imports
from ziggiz_courier_handler_core.decoders import (
    SyslogRFC3164Decoder,
    SyslogRFC5424Decoder,
    SyslogRFCBaseDecoder,
    UnknownSyslogDecoder,
)

# Import the envelope model for docstring references
from ziggiz_courier_handler_core.models.event_envelope_base import (  # noqa
    EventEnvelopeBaseModel,
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

    @staticmethod
    def create_decoder(
        decoder_type: str = "auto",
        connection_cache: Optional[Dict] = None,
        event_parsing_cache: Optional[Dict] = None,
    ):
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

        if decoder_type == "auto":
            return UnknownSyslogDecoder(
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
        elif decoder_type == "rfc3164":
            return SyslogRFC3164Decoder(
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
        elif decoder_type == "rfc5424":
            return SyslogRFC5424Decoder(
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
        elif decoder_type == "base":
            return SyslogRFCBaseDecoder(
                connection_cache=conn_cache,
                event_parsing_cache=event_cache,
            )
        else:
            raise ValueError(
                f"Invalid decoder type: {decoder_type}. "
                "Must be one of: auto, rfc3164, rfc5424, base"
            )

    @staticmethod
    def decode_message(
        decoder_type: str,
        message: str,
        connection_cache: Optional[Dict] = None,
        event_parsing_cache: Optional[Dict] = None,
    ):
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

        Returns:
            The decoded message (an EventEnvelopeBaseModel instance if ziggiz_courier_handler_core is available)

        Raises:
            ImportError: If ziggiz_courier_handler_core is not available
            ValueError: If an invalid decoder type is specified
        """
        # Ensure event_parsing_cache is a dictionary, not None
        event_cache = event_parsing_cache if event_parsing_cache is not None else {}
        conn_cache = connection_cache if connection_cache is not None else {}
        decoder = DecoderFactory.create_decoder(
            decoder_type,
            connection_cache=conn_cache,
            event_parsing_cache=event_cache,
        )
        return decoder.decode(message)
