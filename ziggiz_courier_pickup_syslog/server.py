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
import os
import ssl

from asyncio import AbstractEventLoop, AbstractServer, DatagramTransport
from typing import Optional, Tuple

# Local/package imports
from ziggiz_courier_pickup_syslog.config import Config
from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol
from ziggiz_courier_pickup_syslog.protocol.tls import (
    SyslogTLSProtocol,
    TLSContextBuilder,
)
from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol
from ziggiz_courier_pickup_syslog.protocol.unix import SyslogUnixProtocol


class SyslogServer:
    """
    AsyncIO server implementation for the syslog server.
    This class manages the lifecycle of either a TCP or UDP syslog server
    based on the provided configuration.
    """

    def __init__(self, config: Optional[Config] = None):
        """
        Initialize the syslog server.

        Args:
            config: The configuration object
        """
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.server")
        self.config: Config = config if config is not None else Config()
        self.loop: Optional[AbstractEventLoop] = None
        self.udp_transport: Optional[DatagramTransport] = None
        self.udp_protocol: Optional[SyslogUDPProtocol] = None
        self.tcp_server: Optional[AbstractServer] = None
        self.unix_server: Optional[AbstractServer] = None
        self.tls_server: Optional[AbstractServer] = None
        self.tls_context: Optional[ssl.SSLContext] = None

        # Output backend selection
        self.output_backend = None
        if self.config.output_backend == "kafka":
            # Local/package imports
            from ziggiz_courier_pickup_syslog.kafka_output_backend import (
                KafkaOutputBackend,
            )

            self.output_backend = KafkaOutputBackend(
                bootstrap_servers=self.config.kafka_bootstrap_servers,
                topic=self.config.kafka_topic,
                loop=self.loop,
            )
        else:
            self.output_backend = None  # Console/logging is default

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
            elif protocol == "unix":
                unix_socket_path = self.config.unix_socket_path
                if not unix_socket_path:
                    raise ValueError(
                        "Unix socket path must be provided for Unix protocol"
                    )
                self.unix_server = await self.start_unix_server(unix_socket_path)
                self.logger.info(
                    f"Starting syslog server with UNIX protocol on {unix_socket_path}"
                )
            elif protocol == "tls":
                # Check for required TLS configuration
                if not self.config.tls_certfile or not self.config.tls_keyfile:
                    raise ValueError(
                        "TLS certificate and key files must be provided for TLS protocol"
                    )
                self.tls_server, self.tls_context = await self.start_tls_server(
                    host, port
                )
            else:
                raise ValueError(f"Invalid protocol specified: {protocol}")
        except Exception as e:
            self.logger.error(
                "Failed to start syslog server",
                extra={"error": str(e)},
            )
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
            # Create a factory function to pass configuration options to the protocol
            def protocol_factory() -> SyslogUDPProtocol:
                return SyslogUDPProtocol(
                    decoder_type=self.config.decoder_type,
                    allowed_ips=self.config.allowed_ips,
                    deny_action=self.config.deny_action,
                    enable_model_json_output=self.config.enable_model_json_output,
                    buffer_size=self.config.udp_buffer_size,
                )

            if self.loop is None:
                raise RuntimeError("Event loop is not initialized")
            transport, protocol = await self.loop.create_datagram_endpoint(
                protocol_factory, local_addr=(host, port)
            )
            self.logger.info(
                "UDP server listening",
                extra={"host": host, "port": port},
            )
            return transport, protocol
        except Exception as e:
            self.logger.error(
                "Failed to start UDP server",
                extra={"error": str(e)},
            )
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
            # Create a factory function to pass configuration options to the protocol
            def protocol_factory() -> SyslogTCPProtocol:
                return SyslogTCPProtocol(
                    framing_mode=self.config.framing_mode,
                    end_of_message_marker=self.config.end_of_message_marker,
                    max_message_length=self.config.max_message_length,
                    decoder_type=self.config.decoder_type,
                    allowed_ips=self.config.allowed_ips,
                    deny_action=self.config.deny_action,
                    enable_model_json_output=self.config.enable_model_json_output,
                )

            if self.loop is None:
                raise RuntimeError("Event loop is not initialized")
            server = await self.loop.create_server(protocol_factory, host, port)
            self.logger.info(
                f"TCP server listening on {host}:{port} with framing mode: {self.config.framing_mode}"
            )
            return server
        except Exception as e:
            self.logger.error(
                "Failed to start TCP server",
                extra={"error": str(e)},
            )
            raise

    async def start_unix_server(self, socket_path: str) -> asyncio.AbstractServer:
        """
        Start a Unix Stream syslog server.

        Args:
            socket_path: The path to the Unix domain socket

        Returns:
            The server object

        Raises:
            Exception: If the server cannot be started
        """
        try:
            # Remove the socket file if it already exists
            if os.path.exists(socket_path):
                os.unlink(socket_path)

            # Create the directory for the socket if it doesn't exist
            socket_dir = os.path.dirname(socket_path)
            if socket_dir and not os.path.exists(socket_dir):
                os.makedirs(socket_dir, exist_ok=True)

            # Create a factory function to pass configuration options to the protocol
            def protocol_factory() -> SyslogUnixProtocol:
                return SyslogUnixProtocol(
                    framing_mode=self.config.framing_mode,
                    end_of_message_marker=self.config.end_of_message_marker,
                    max_message_length=self.config.max_message_length,
                    decoder_type=self.config.decoder_type,
                    # Unix sockets don't need IP filtering
                )

            if self.loop is None:
                raise RuntimeError("Event loop is not initialized")
            server = await self.loop.create_unix_server(protocol_factory, socket_path)
            self.logger.info(
                f"Unix Stream server listening on {socket_path} with framing mode: {self.config.framing_mode}"
            )
            return server
        except Exception as e:
            self.logger.error(
                "Failed to start Unix Stream server",
                extra={"error": str(e)},
            )
            raise

    async def start_tls_server(
        self, host: str, port: int
    ) -> Tuple[asyncio.AbstractServer, ssl.SSLContext]:
        """
        Start a TLS syslog server.

        Args:
            host: The host address to bind to
            port: The port to listen on

        Returns:
            A tuple of (server, ssl_context)

        Raises:
            Exception: If the server cannot be started
        """
        try:
            # Get TLS configuration from config
            certfile = self.config.tls_certfile
            keyfile = self.config.tls_keyfile
            ca_certs = self.config.tls_ca_certs
            verify_client = self.config.tls_verify_client

            # Convert string TLS version to enum
            tls_version_str = self.config.tls_min_version
            if tls_version_str == "TLSv1_2":
                min_version = ssl.TLSVersion.TLSv1_2
            else:  # Default to TLSv1_3
                min_version = ssl.TLSVersion.TLSv1_3

            ciphers = self.config.tls_ciphers

            # Get certificate verification rules if configured
            cert_rules = None
            if self.config.tls_cert_rules:
                cert_rules = [rule.dict() for rule in self.config.tls_cert_rules]
                self.logger.info(
                    f"Using {len(cert_rules)} certificate verification rules"
                )

            # Validate certfile and keyfile (they should have been checked earlier, but double check)
            if not certfile:
                raise ValueError("Certificate file is required for TLS server")
            if not keyfile:
                raise ValueError("Key file is required for TLS server")

            # Create SSL context and certificate verifier
            # We've validated that certfile and keyfile are not None earlier in the function
            ssl_context, cert_verifier = TLSContextBuilder.create_server_context(
                certfile=certfile,  # Validated not None
                keyfile=keyfile,  # Validated not None
                ca_certs=ca_certs,
                verify_client=verify_client,
                min_version=min_version,
                ciphers=ciphers,
                cert_rules=cert_rules,
            )

            # Create a factory function to pass configuration options to the protocol
            def protocol_factory() -> SyslogTLSProtocol:
                return SyslogTLSProtocol(
                    framing_mode=self.config.framing_mode,
                    end_of_message_marker=self.config.end_of_message_marker,
                    max_message_length=self.config.max_message_length,
                    decoder_type=self.config.decoder_type,
                    cert_verifier=cert_verifier,
                    allowed_ips=self.config.allowed_ips,
                    deny_action=self.config.deny_action,
                    enable_model_json_output=self.config.enable_model_json_output,
                )

            # Create the server
            if self.loop is None:
                raise RuntimeError("Event loop is not initialized")
            server = await self.loop.create_server(
                protocol_factory,
                host,
                port,
                ssl=ssl_context,
            )

            # Log server information
            self.logger.info(
                f"TLS server listening on {host}:{port} with framing mode: {self.config.framing_mode}, "
                f"TLS version: {tls_version_str}"
            )

            return server, ssl_context
        except Exception as e:
            self.logger.error(
                "Failed to start TLS server",
                extra={"error": str(e)},
            )
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

        # Clean up Unix resources
        if self.unix_server:
            self.logger.debug("Closing Unix Stream server")
            # Server's close method is synchronous, no need to await it
            self.unix_server.close()
            # But wait_closed is a coroutine that needs to be awaited
            await self.unix_server.wait_closed()
            self.unix_server = None

            # Remove the Unix socket file if it exists
            socket_path = self.config.unix_socket_path
            if socket_path and os.path.exists(socket_path):
                try:
                    os.unlink(socket_path)
                    self.logger.debug(f"Removed Unix socket file: {socket_path}")
                except OSError as e:
                    self.logger.warning(
                        "Error removing Unix socket file",
                        extra={"error": str(e)},
                    )

        # Clean up TLS resources
        if self.tls_server:
            self.logger.debug("Closing TLS server")
            # TLS server's close method is synchronous, no need to await it
            self.tls_server.close()
            # But wait_closed is a coroutine that needs to be awaited
            await self.tls_server.wait_closed()
            self.tls_server = None
            self.tls_context = None

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
        if self.udp_transport or self.tcp_server or self.unix_server or self.tls_server:
            self.logger.warning("Server resources not properly cleaned up.")
            # We can't run async code in __del__, so just log a warning
