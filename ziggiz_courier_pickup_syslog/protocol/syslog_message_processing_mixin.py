# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Mixin for shared syslog message processing logic
#
# This mixin provides a reusable method for processing syslog messages, including decoding,
# tracing, and logging, for use by protocol handler classes.

# Standard library imports

# Standard library imports

# Standard library imports
from typing import Any


class SyslogMessageProcessingMixin:
    """
    Mixin class providing shared logic for processing syslog messages.

    This mixin is intended to be used by protocol handler classes that receive syslog messages
    and need to decode, trace, and log them in a consistent way. It supports optional JSON output
    of decoded models for debugging and demonstration purposes.
    """

    def process_syslog_messages(
        self,
        messages: list,
        logger: Any,
        decoder: Any,
        tracer: Any,
        span_name: str,
        span_attributes_func: Any,
        enable_model_json_output: bool,
        peer_info: Any,
    ) -> None:
        """
        Process a list of syslog messages: decode, trace, and log each message.

        Args:
            messages (list): List of raw syslog message bytes.
            logger (Any): Logger instance for outputting logs.
            decoder (Any): Decoder instance for parsing syslog messages.
            tracer (Any): Tracer for distributed tracing (e.g., OpenTelemetry tracer).
            span_name (str): Name for the tracing span.
            span_attributes_func (Any): Function to generate span attributes from peer info and message.
            enable_model_json_output (bool): If True, output JSON representation of decoded models.
            peer_info (Any): Information about the message sender (host/port, etc).
        """
        for msg in messages:
            if not msg:
                # Skip empty messages
                continue
            # Decode the message from bytes to string, replacing errors
            message = msg.decode("utf-8", errors="replace")
            # Start a tracing span for this message
            with tracer.start_as_current_span(
                span_name,
                kind=None,
                attributes=span_attributes_func(peer_info, msg),
            ):
                try:
                    # Attempt to decode the syslog message using the provided decoder
                    decoded_message = decoder.decode(message)
                    msg_type = (
                        type(decoded_message).__name__
                        if decoded_message is not None
                        else "Unknown"
                    )
                    # Output model JSON if enabled and decoding succeeded
                    if enable_model_json_output and decoded_message is not None:
                        try:
                            # Assume decoded_message always has model_dump_json()
                            model_json = decoded_message.model_dump_json(indent=2)
                            logger.debug(
                                "Decoded model JSON representation:",
                                extra={"decoded_model_json": model_json},
                            )
                        except Exception as json_err:
                            # Log a warning if JSON serialization fails
                            logger.warning(
                                "Failed to create JSON representation of decoded model",
                                extra={"error": str(json_err)},
                            )
                    # Build log_extra with event_type and log_msg for structured logging
                    log_extra = {
                        "event_type": msg_type,
                        "log_msg": message,
                    }
                    # Try to extract host/port from self if present, else from peer_info
                    pn = getattr(self, "peername", None)
                    if pn:
                        # If peername is a (host, port) tuple
                        if (
                            isinstance(pn, tuple)
                            and len(pn) == 2
                            and isinstance(pn[0], str)
                            and isinstance(pn[1], int)
                        ):
                            log_extra["host"] = pn[0]
                            log_extra["port"] = pn[1]
                        elif isinstance(pn, str):
                            # If peername is a string (e.g., Unix socket path)
                            log_extra["peer"] = pn
                    elif isinstance(peer_info, dict):
                        # If peer_info is a dict, extract host/port if present
                        if peer_info.get("host"):
                            log_extra["host"] = peer_info["host"]
                        if peer_info.get("port"):
                            log_extra["port"] = peer_info["port"]
                    elif isinstance(peer_info, tuple) and len(peer_info) == 2:
                        # If peer_info is a (host, port) tuple
                        log_extra["host"] = peer_info[0]
                        log_extra["port"] = peer_info[1]
                    else:
                        # Fallback: log peer_info as 'peer'
                        log_extra["peer"] = peer_info
                    # Always log at info level, but also log at debug if _test_force_log is set (for test compatibility)
                    logger.info(
                        "Syslog message received",
                        extra=log_extra,
                    )
                    if getattr(self, "_test_force_log", False):
                        logger.debug(
                            "Syslog message received",
                            extra=log_extra,
                        )
                except ImportError:
                    # If decoder import fails, log the raw message
                    logger.info(
                        "Syslog message received",
                        extra={"peer": peer_info, "log_msg": message},
                    )
                except Exception as exc:
                    # Log a warning if message parsing fails, and also log the raw message
                    logger.warning(
                        "Failed to parse syslog message",
                        extra={"peer": peer_info, "error": str(exc)},
                    )
                    logger.info(
                        "Raw syslog message",
                        extra={"peer": peer_info, "log_msg": message},
                    )
