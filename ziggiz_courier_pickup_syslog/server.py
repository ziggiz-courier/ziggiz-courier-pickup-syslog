# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Server implementation for the syslog server

# Standard library imports
import asyncio
import logging

from typing import Optional, Tuple

# Local/package imports
# Local imports
from ziggiz_courier_pickup_syslog.config import Config
from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol
from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol


class SyslogServer:
    """
    AsyncIO server implementation for the syslog server.
    This class manages the lifecycle of either a TCP or UDP syslog server
    based on the provided configuration.
    """

    def __init__(self, config: Config = None):
        """
        Initialize the syslog server.

        Args:
            config: The configuration object
        """
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.server")
        self.config = config or Config()
        self.loop = None
        self.udp_transport = None
        self.udp_protocol = None
        self.tcp_server = None

    async def start(self, loop: Optional[asyncio.AbstractEventLoop] = None) -> None:
        """
        Start the syslog server.

        Args:
            loop: Optional event loop to use

        Raises:
            RuntimeError: If the server fails to start
        """
        # Get the event loop if not provided
        self.loop = loop or asyncio.get_event_loop()

        host = self.config.host
        port = self.config.port
        protocol = self.config.protocol.lower()

        self.logger.info(
            f"Starting syslog server on {host} using {protocol.upper()} protocol on port {port}"
        )

        try:
            if protocol == "udp":
                self.udp_transport, self.udp_protocol = await self.start_udp_server(
                    host, port
                )
            elif protocol == "tcp":
                self.tcp_server = await self.start_tcp_server(host, port)
            else:
                raise ValueError(f"Invalid protocol specified: {protocol}")
        except Exception as e:
            self.logger.error(f"Failed to start syslog server: {e}")
            raise RuntimeError(f"Failed to start syslog server: {e}")

    async def start_udp_server(
        self, host: str, port: int
    ) -> Tuple[asyncio.DatagramTransport, SyslogUDPProtocol]:
        """
        Start a UDP syslog server.

        Args:
            host: The host address to bind to
            port: The port to listen on

        Returns:
            A tuple of (transport, protocol)

        Raises:
            Exception: If the server cannot be started
        """
        try:
            transport, protocol = await self.loop.create_datagram_endpoint(
                SyslogUDPProtocol, local_addr=(host, port)
            )
            self.logger.info(f"UDP server listening on {host}:{port}")
            return transport, protocol
        except Exception as e:
            self.logger.error(f"Failed to start UDP server: {e}")
            raise

    async def start_tcp_server(self, host: str, port: int) -> asyncio.AbstractServer:
        """
        Start a TCP syslog server.

        Args:
            host: The host address to bind to
            port: The port to listen on

        Returns:
            The server object

        Raises:
            Exception: If the server cannot be started
        """
        try:
            server = await self.loop.create_server(SyslogTCPProtocol, host, port)
            self.logger.info(f"TCP server listening on {host}:{port}")
            return server
        except Exception as e:
            self.logger.error(f"Failed to start TCP server: {e}")
            raise

    async def stop(self) -> None:
        """
        Stop the syslog server.
        """
        self.logger.info("Stopping syslog server")

        # Clean up UDP resources
        if self.udp_transport:
            self.logger.debug("Closing UDP transport")
            self.udp_transport.close()
            self.udp_transport = None
            self.udp_protocol = None

        # Clean up TCP resources
        if self.tcp_server:
            self.logger.debug("Closing TCP server")
            # TCP server's close method is synchronous, no need to await it
            self.tcp_server.close()
            # But wait_closed is a coroutine that needs to be awaited
            await self.tcp_server.wait_closed()
            self.tcp_server = None

    async def run_forever(self) -> None:
        """
        Run the server until interrupted.
        """
        try:
            await self.start()
            # Keep the server running
            while True:
                await asyncio.sleep(3600)  # Just to keep the task alive
        except asyncio.CancelledError:
            self.logger.info("Server task cancelled")
        except KeyboardInterrupt:
            self.logger.info("Keyboard interrupt received")
        finally:
            await self.stop()

    def __del__(self) -> None:
        """
        Clean up resources when the object is garbage collected.
        """
        if self.udp_transport or self.tcp_server:
            self.logger.warning("Server resources not properly cleaned up.")
            # We can't run async code in __del__, so just log a warning
