# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
"""
Async mixin for syslog message processing that outputs to Kafka using aiokafka.
"""
# Standard library imports

# Standard library imports
from typing import Any, Optional

# Local/package imports
from ziggiz_courier_pickup_syslog.kafka_output_backend import KafkaOutputBackend


class SyslogKafkaOutputMixin:
    """
    Mixin for processing syslog messages and sending them to Kafka asynchronously.
    """

    kafka_backend: Optional[KafkaOutputBackend] = None

    async def process_syslog_messages_to_kafka(
        self,
        messages: list,
        decoder: Any,
        kafka_backend: KafkaOutputBackend,
        peer_info: Any,
        key_func: Optional[Any] = None,
        value_func: Optional[Any] = None,
    ) -> None:
        """
        Process syslog messages and send them to Kafka.

        Args:
            messages (list): List of raw syslog message bytes.
            decoder (Any): Decoder instance for parsing syslog messages.
            kafka_backend (KafkaOutputBackend): Kafka backend instance.
            peer_info (Any): Information about the message sender.
            key_func (callable, optional): Function to generate Kafka key from message.
            value_func (callable, optional): Function to generate Kafka value from decoded message.
        """
        await kafka_backend.start()
        for msg in messages:
            if not msg:
                continue
            message = msg.decode("utf-8", errors="replace")
            try:
                decoded_message = decoder.decode(message)
                # Use value_func if provided, else default to model_dump_json or str
                if value_func:
                    value = value_func(decoded_message)
                elif hasattr(decoded_message, "model_dump_json"):
                    value = decoded_message.model_dump_json().encode("utf-8")
                else:
                    value = str(decoded_message).encode("utf-8")
                # Use key_func if provided, else None
                key = key_func(decoded_message) if key_func else None
                await kafka_backend.send(value=value, key=key)
            except Exception:
                # Optionally log or handle errors here
                pass
