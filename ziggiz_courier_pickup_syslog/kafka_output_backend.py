# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
"""
Kafka output backend for syslog message processing (asyncio, aiokafka).
"""
# Standard library imports
import asyncio
import logging

from typing import Any, Optional

# Third-party imports
from aiokafka import AIOKafkaProducer


class KafkaOutputBackend:
    """
    Async output backend that sends syslog messages to Kafka using aiokafka.
    """

    def __init__(
        self,
        bootstrap_servers: str,
        topic: str,
        loop: Optional[asyncio.AbstractEventLoop] = None,
        **producer_kwargs: Any,
    ):
        self.bootstrap_servers = bootstrap_servers
        self.topic = topic
        self.loop = loop or asyncio.get_event_loop()
        self.producer = AIOKafkaProducer(
            loop=self.loop, bootstrap_servers=self.bootstrap_servers, **producer_kwargs
        )
        self._started = False
        self.logger = logging.getLogger("KafkaOutputBackend")

    async def start(self) -> None:
        if not self._started:
            await self.producer.start()
            self._started = True
            self.logger.info("Kafka producer started.")

    async def stop(self) -> None:
        if self._started:
            await self.producer.stop()
            self._started = False
            self.logger.info("Kafka producer stopped.")

    async def send(
        self, value: bytes, key: Optional[bytes] = None, headers: Optional[list] = None
    ) -> None:
        if not self._started:
            await self.start()
        try:
            await self.producer.send_and_wait(
                self.topic, value=value, key=key, headers=headers
            )
            self.logger.debug("Message sent to Kafka topic %s", self.topic)
        except Exception as exc:
            self.logger.error("Failed to send message to Kafka: %s", exc)
