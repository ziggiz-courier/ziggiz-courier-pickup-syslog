# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Abstract base class for buffered streaming syslog protocols

# Standard library imports
import asyncio
import logging

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.decoder_factory import DecoderFactory
from ziggiz_courier_pickup_syslog.protocol.framing import (
    FramingDetectionError,
    FramingHelper,
    FramingMode,
)
from ziggiz_courier_pickup_syslog.protocol.syslog_message_processing_mixin import (
    SyslogMessageProcessingMixin,
)
from ziggiz_courier_pickup_syslog.telemetry import get_tracer


class BaseSyslogBufferedProtocol(
    SyslogMessageProcessingMixin, asyncio.BufferedProtocol, ABC
):
    """
    Abstract base class for syslog buffered streaming protocols (TCP/Unix).
    Implements shared logic for framing, decoding, and buffer management.
    """

    def __init__(
        self,
        framing_mode: str = "auto",
        end_of_message_marker: str = "\\n",
        max_message_length: int = 16 * 1024,
        decoder_type: str = "auto",
        enable_model_json_output: bool = False,
    ):
        self.logger = logging.getLogger(self.logger_name)
        self.transport: Optional[asyncio.BaseTransport] = None
        self._test_force_log = False
        self._test_force_log: bool = False
        self.decoder_type = decoder_type
        self.enable_model_json_output = enable_model_json_output
        self.connection_cache: Dict[Any, Any] = {}
        self.event_parsing_cache: Dict[Any, Any] = {}
        self.decoder = DecoderFactory.create_decoder(
            self.decoder_type,
            connection_cache=self.connection_cache,
        )
        framing_enum = None
        framing_mode_map = {
            "auto": FramingMode.AUTO,
            "framingmode.auto": FramingMode.AUTO,
            "transparent": FramingMode.TRANSPARENT,
            "framingmode.transparent": FramingMode.TRANSPARENT,
            "non_transparent": FramingMode.NON_TRANSPARENT,
            "nontransparent": FramingMode.NON_TRANSPARENT,
            "non-transparent": FramingMode.NON_TRANSPARENT,
            "non transparent": FramingMode.NON_TRANSPARENT,
            "framingmode.non_transparent": FramingMode.NON_TRANSPARENT,
        }
        try:
            # Accept both FramingMode enums and strings (case-insensitive, underscore-insensitive)
            if isinstance(framing_mode, FramingMode):
                framing_enum = framing_mode
            elif isinstance(framing_mode, str):
                normalized = (
                    framing_mode.strip().replace("-", "_").replace(" ", "_").lower()
                )
                if normalized in framing_mode_map:
                    framing_enum = framing_mode_map[normalized]
                else:
                    raise ValueError(f"Invalid framing_mode string: {framing_mode}")
            else:
                raise ValueError(f"Invalid framing_mode: {framing_mode}")
            end_marker_bytes = FramingHelper.parse_end_of_msg_marker(
                end_of_message_marker
            )
            self.logger.debug(
                f"Initializing FramingHelper with mode: {framing_enum}, marker: {end_marker_bytes!r}"
            )
            self.framing_helper = FramingHelper(
                framing_mode=framing_enum,
                end_of_msg_marker=end_marker_bytes,
                max_msg_length=max_message_length,
                logger=self.logger,
            )
        except (ValueError, FramingDetectionError) as e:
            self.logger.error(
                "Error setting up framing",
                extra={"error": e, "framing_mode": framing_enum},
            )
            # Fallback: preserve intended framing_enum if possible, else default to AUTO
            fallback_mode = (
                framing_enum if framing_enum is not None else FramingMode.AUTO
            )
            self.framing_helper = FramingHelper(
                framing_mode=fallback_mode, logger=self.logger
            )
        self._read_buffer: Optional[bytearray] = None
        self.max_buffer_size = 65536

    @property
    @abstractmethod
    def logger_name(self) -> str:
        pass

    @abstractmethod
    def get_peer_info(self) -> Any:
        pass

    def get_buffer(self, sizehint: int) -> bytearray:
        buffer_size = min(sizehint, self.max_buffer_size)
        self._read_buffer = bytearray(buffer_size)
        return self._read_buffer

    def buffer_updated(self, nbytes: int) -> None:
        # Determine peer info for logging (TCP/Unix protocols may use different attributes)
        peer_info = self.get_peer_info() if hasattr(self, "get_peer_info") else None
        tracer = get_tracer()

        # Correctly handle IP vs Unix socket peername
        host, port, peer = None, None, None
        if hasattr(self, "peername") and getattr(self, "peername", None):
            pn = self.peername
            # IP socket: tuple of (str, int)
            if (
                isinstance(pn, tuple)
                and len(pn) == 2
                and isinstance(pn[0], str)
                and isinstance(pn[1], int)
            ):
                host, port = pn
            # Unix socket: str
            elif isinstance(pn, str):
                peer = pn
        elif isinstance(peer_info, dict):
            host = peer_info.get("host")
            port = peer_info.get("port")
        elif isinstance(peer_info, tuple) and len(peer_info) == 2:
            host, port = peer_info

        log_extra = {"nbytes": nbytes}
        if host is not None:
            log_extra["host"] = host
        if port is not None:
            log_extra["port"] = port
        if peer is not None:
            log_extra["peer"] = peer
        self.logger.debug("Received data", extra=log_extra)

        if self._read_buffer is None:
            self.logger.error("Buffer is None in buffer_updated")
            return
        data = self._read_buffer[:nbytes]
        try:
            self.framing_helper.add_data(data)
            if self.framing_helper.framing_mode == FramingMode.TRANSPARENT or (
                self.framing_helper.framing_mode == FramingMode.AUTO
                and getattr(self.framing_helper, "_detected_mode", None)
                == FramingMode.TRANSPARENT
            ):
                self.logger.debug(
                    "Buffer size after adding data",
                    extra={"buffer_size": self.framing_helper.buffer_size},
                )
            messages = self.framing_helper.extract_messages()
            self.process_syslog_messages(
                messages=messages,
                logger=self.logger,
                decoder=self.decoder,
                tracer=tracer,
                span_name=self.span_name,
                span_attributes_func=self.span_attributes,
                enable_model_json_output=self.enable_model_json_output,
                peer_info=peer_info,
            )
        except FramingDetectionError as exc:
            self.logger.error("Framing error", extra={"peer": peer_info, "error": exc})
            self.logger.warning("Closing connection due to framing error")
            if self.transport:
                self.transport.close()
        except Exception as exc:
            self.logger.error(
                "Unexpected error in buffer_updated",
                extra={"peer": peer_info, "error": str(exc)},
            )

    @property
    @abstractmethod
    def span_name(self) -> str:

        pass

    @abstractmethod
    def span_attributes(self, peer_info, msg) -> dict:
        pass

    def eof_received(self) -> bool:
        peer_info = self.get_peer_info()
        self.logger.debug("EOF received", extra={"peer": peer_info})
        try:
            buffer_data = bytes(self.framing_helper._buffer)
            messages = self.framing_helper.extract_messages()
            for msg in messages:
                if msg:
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
                                        # Standard library imports
                                        import json

                                        model_json = json.dumps(
                                            decoded_message.model_dump(),
                                            default=str,
                                            indent=2,
                                        )
                                    elif hasattr(decoded_message, "dict") and callable(
                                        getattr(decoded_message, "dict", None)
                                    ):
                                        # Standard library imports
                                        import json

                                        model_json = json.dumps(
                                            decoded_message.dict(),
                                            default=str,
                                            indent=2,
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
                            f"Final syslog message ({msg_type}) from {peer_info}: {message}"
                        )
                    except ImportError:
                        self.logger.info(
                            f"Final syslog message from {peer_info}: {message}"
                        )
                    except Exception as exc:
                        self.logger.warning(
                            f"Failed to parse final syslog message from {peer_info}: {exc}"
                        )
                        self.logger.info(
                            f"Raw final syslog message from {peer_info}: {message}"
                        )
            if not messages and buffer_data:
                message = buffer_data.decode("utf-8", errors="replace")
                try:
                    decoded_message = self.decoder.decode(message)
                    if decoded_message is not None and self.enable_model_json_output:
                        try:
                            if hasattr(decoded_message, "model_dump_json"):
                                model_json = decoded_message.model_dump_json(indent=2)
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
                                    # Standard library imports
                                    import json

                                    model_dict = dump_method()
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
                        f"Final syslog message ({msg_type}) from {peer_info}: {message}"
                    )
                except ImportError:
                    self.logger.info(
                        f"Final syslog message from {peer_info}: {message}"
                    )
                except Exception as exc:
                    self.logger.warning(
                        f"Failed to parse final syslog message from {peer_info}: {exc}"
                    )
                    self.logger.info(
                        f"Raw final syslog message from {peer_info}: {message}"
                    )
                self.framing_helper._buffer.clear()
            if self.framing_helper.buffer_size > 0:
                self.logger.warning(
                    f"Discarding {self.framing_helper.buffer_size} bytes of unparsed data from {peer_info}"
                )
        except Exception as exc:
            self.logger.error(f"Error processing final data from {peer_info}: {exc}")
        return False

    def connection_lost(self, exc: Optional[Exception]) -> None:
        peer_info = self.get_peer_info()
        if exc:
            self.logger.warning(f"Connection from {peer_info} closed with error: {exc}")
        else:
            self.logger.debug(f"Connection from {peer_info} closed")
        self.framing_helper.reset()
        self._read_buffer = None
        self.transport = None

    @property
    def buffer(self) -> bytes:
        return self.framing_helper._buffer

    @buffer.setter
    def buffer(self, value: bytes) -> None:
        self.framing_helper._buffer.clear()
        self.framing_helper._buffer.extend(value)
