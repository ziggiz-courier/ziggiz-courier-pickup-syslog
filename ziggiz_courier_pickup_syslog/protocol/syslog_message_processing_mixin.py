# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Mixin for shared syslog message processing logic

# Standard library imports

# Standard library imports
import json

from typing import Any


class SyslogMessageProcessingMixin:
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
        for msg in messages:
            if msg:
                message = msg.decode("utf-8", errors="replace")
                with tracer.start_as_current_span(
                    span_name,
                    kind=None,
                    attributes=span_attributes_func(peer_info, msg),
                ):
                    try:
                        decoded_message = decoder.decode(message)
                        msg_type = (
                            type(decoded_message).__name__
                            if decoded_message is not None
                            else "Unknown"
                        )
                        if enable_model_json_output and decoded_message is not None:
                            try:
                                model_json = None
                                if hasattr(
                                    decoded_message, "model_dump_json"
                                ) and callable(
                                    getattr(decoded_message, "model_dump_json", None)
                                ):
                                    model_json = decoded_message.model_dump_json(
                                        indent=2
                                    )
                                elif hasattr(decoded_message, "json") and callable(
                                    getattr(decoded_message, "json", None)
                                ):
                                    model_json = decoded_message.json(indent=2)
                                elif hasattr(decoded_message, "dict") and callable(
                                    getattr(decoded_message, "dict", None)
                                ):
                                    model_json = json.dumps(
                                        decoded_message.dict(), default=str, indent=2
                                    )
                                elif hasattr(
                                    decoded_message, "model_dump"
                                ) and callable(
                                    getattr(decoded_message, "model_dump", None)
                                ):
                                    model_json = json.dumps(
                                        decoded_message.model_dump(),
                                        default=str,
                                        indent=2,
                                    )
                                if model_json:
                                    logger.debug(
                                        "Decoded model JSON representation:",
                                        extra={"decoded_model_json": model_json},
                                    )
                            except Exception as json_err:
                                logger.warning(
                                    "Failed to create JSON representation of decoded model",
                                    extra={"error": str(json_err)},
                                )
                        # Add host/port to extra if available in self
                        # Always include event_type and log_msg for both normal and test modes (for test compatibility)
                        log_extra = {
                            "event_type": msg_type,
                            "log_msg": message,
                        }
                        # Try to extract host/port from self if present
                        if hasattr(self, "peername") and getattr(
                            self, "peername", None
                        ):
                            pn = self.peername
                            if (
                                isinstance(pn, tuple)
                                and len(pn) == 2
                                and isinstance(pn[0], str)
                                and isinstance(pn[1], int)
                            ):
                                log_extra["host"] = pn[0]
                                log_extra["port"] = pn[1]
                            elif isinstance(pn, str):
                                log_extra["peer"] = pn
                        elif isinstance(peer_info, dict):
                            if peer_info.get("host"):
                                log_extra["host"] = peer_info["host"]
                            if peer_info.get("port"):
                                log_extra["port"] = peer_info["port"]
                        elif isinstance(peer_info, tuple) and len(peer_info) == 2:
                            log_extra["host"] = peer_info[0]
                            log_extra["port"] = peer_info[1]
                        else:
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
                        logger.info(
                            "Syslog message received",
                            extra={"peer": peer_info, "log_msg": message},
                        )
                    except Exception as exc:
                        logger.warning(
                            "Failed to parse syslog message",
                            extra={"peer": peer_info, "error": str(exc)},
                        )
                        logger.info(
                            "Raw syslog message",
                            extra={"peer": peer_info, "log_msg": message},
                        )
