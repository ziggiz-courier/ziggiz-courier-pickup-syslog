# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# TLS Protocol implementation for syslog server with fixed framing

# Standard library imports
import asyncio
import logging
import ssl

from typing import Dict, List, Optional, Tuple, Union

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.cert_verify import (
    CertificateVerifier,
    create_verifier_from_config,
)
from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol


class SyslogTLSProtocol(SyslogTCPProtocol):
    """
    TLS Protocol implementation for handling syslog messages.

    This class extends the SyslogTCPProtocol to add TLS support.
    It uses the same framing and message handling logic as the TCP protocol
    but adds TLS encryption for secure communication.
    """

    def __init__(
        self,
        framing_mode: str = "auto",
        end_of_message_marker: str = "\\n",
        max_message_length: int = 16 * 1024,
        decoder_type: str = "auto",
        cert_verifier: Optional[CertificateVerifier] = None,
        allowed_ips: Optional[List[str]] = None,
        deny_action: str = "drop",
        enable_model_json_output: bool = False,
    ):
        """
        Initialize the TLS protocol.

        Args:
            framing_mode: The framing mode to use ("auto", "transparent", or "non_transparent")
            end_of_message_marker: The marker indicating end of message for non-transparent framing
            max_message_length: Maximum message length for non-transparent framing
            decoder_type: The type of syslog decoder to use ("auto", "rfc3164", "rfc5424", or "base")
            cert_verifier: Optional certificate verifier for client certificate validation
            allowed_ips: List of allowed IP addresses/networks (empty list means allow all)
            deny_action: Action to take for denied connections: "drop" or "reject"
            enable_model_json_output: Whether to generate JSON output of decoded models (for demos/debugging)
        """
        super().__init__(
            framing_mode=framing_mode,
            end_of_message_marker=end_of_message_marker,
            max_message_length=max_message_length,
            decoder_type=decoder_type,
            allowed_ips=allowed_ips,
            deny_action=deny_action,
            enable_model_json_output=enable_model_json_output,
        )
        # Override the logger name for TLS
        self.logger = logging.getLogger("ziggiz_courier_pickup_syslog.protocol.tls")
        self.cert_verifier = cert_verifier

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        """
        Called when a connection is made.

        Args:
            transport: The transport for the connection
        """
        self.transport = transport
        self.peername = transport.get_extra_info("peername")
        host, port = self.peername if self.peername else ("unknown", "unknown")

        # Check if the IP is allowed
        if host != "unknown" and not self.ip_filter.is_allowed(host):
            if self.deny_action == "reject":
                # Send a rejection message before closing
                self.logger.warning(
                    "Rejected TLS connection (not in allowed IPs)",
                    extra={"host": host, "port": port},
                )
                # We can't send a proper rejection message in TLS, so just close the connection
                transport.close()
            else:  # "drop"
                self.logger.warning(
                    "Dropped TLS connection (not in allowed IPs)",
                    extra={"host": host, "port": port},
                )
                transport.close()
            return

        # Get SSL information
        ssl_object = transport.get_extra_info("ssl_object")

        if ssl_object:
            # Log TLS-specific information
            cipher = ssl_object.cipher()
            version = ssl_object.version()
            self.logger.info(
                "TLS connection established",
                extra={
                    "host": host,
                    "port": port,
                    "version": version,
                    "cipher": cipher[0],
                    "bits": cipher[2],
                },
            )

            # Log and verify client certificate if available
            peer_cert = ssl_object.getpeercert()
            if peer_cert:
                self._log_certificate_info(peer_cert, host, port)

                # Verify certificate attributes if a verifier is configured
                if self.cert_verifier:
                    if not self.cert_verifier.verify_certificate(ssl_object):
                        self.logger.warning(
                            "Client certificate failed attribute verification",
                            extra={"host": host, "port": port},
                        )
                        # We don't close the connection here because the SSL handshake has already
                        # completed. The application layer will need to decide how to handle this.
            else:
                self.logger.warning(
                    "No client certificate provided", extra={"host": host, "port": port}
                )
        else:
            self.logger.warning(
                "TLS connection established but SSL information is not available",
                extra={"host": host, "port": port},
            )

    def _log_certificate_info(
        self, cert: Dict, host: str, port: Union[str, int]
    ) -> None:
        """
        Log information about a client certificate.

        Args:
            cert: The certificate dictionary
            host: The client host
            port: The client port
        """
        # Extract and log certificate subject information
        subject = cert.get("subject", [])
        subject_str = ", ".join([f"{name}={value}" for ((name, value),) in subject])

        # Extract and log certificate issuer information
        issuer = cert.get("issuer", [])
        issuer_str = ", ".join([f"{name}={value}" for ((name, value),) in issuer])

        # Log certificate validity period
        not_before = cert.get("notBefore", "unknown")
        not_after = cert.get("notAfter", "unknown")

        self.logger.info(
            "Client certificate information",
            extra={
                "host": host,
                "port": port,
                "subject": subject_str,
                "issuer": issuer_str,
                "valid_from": not_before,
                "valid_to": not_after,
            },
        )


class TLSContextBuilder:
    """
    Helper class to build SSL contexts for TLS connections.

    This class provides methods to create and configure SSL contexts
    with appropriate security settings for syslog over TLS.
    """

    @staticmethod
    def create_server_context(
        certfile: str,
        keyfile: str,
        ca_certs: Optional[str] = None,
        verify_client: bool = False,
        min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
        ciphers: Optional[str] = None,
        cert_rules: Optional[List[Dict[str, Union[str, bool]]]] = None,
    ) -> Tuple[ssl.SSLContext, Optional[CertificateVerifier]]:
        """
        Create an SSL context for the server.

        Args:
            certfile: Path to the server certificate file
            keyfile: Path to the server private key file
            ca_certs: Path to the CA certificates file for client verification
            verify_client: Whether to verify client certificates
            min_version: Minimum TLS version to accept (default: TLS 1.3)
            ciphers: Optional cipher string to restrict allowed ciphers
            cert_rules: Optional list of certificate verification rules

        Returns:
            Tuple of (configured SSL context, certificate verifier or None)
        """
        # Create a server-side SSL context
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)

        # Load server certificate and private key
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # Set minimum TLS version
        context.minimum_version = min_version

        # Set cipher suite if specified
        if ciphers:
            context.set_ciphers(ciphers)

        # Initialize certificate verifier if rules are provided
        cert_verifier = None
        if cert_rules:
            cert_verifier = create_verifier_from_config(cert_rules)

        # Configure client certificate verification if requested
        if verify_client:
            if ca_certs:
                context.load_verify_locations(cafile=ca_certs)
            else:
                raise ValueError(
                    "CA certificates file must be provided when verify_client is True"
                )

            context.verify_mode = ssl.CERT_REQUIRED

        return context, cert_verifier


async def create_tls_server(
    host: str,
    port: int,
    certfile: str,
    keyfile: str,
    ca_certs: Optional[str] = None,
    verify_client: bool = False,
    min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    ciphers: Optional[str] = None,
    framing_mode: str = "auto",
    end_of_message_marker: str = "\\n",
    max_message_length: int = 16 * 1024,
    decoder_type: str = "auto",
    cert_rules: Optional[List[Dict[str, Union[str, bool]]]] = None,
    enable_model_json_output: bool = False,
) -> Tuple[asyncio.AbstractServer, ssl.SSLContext]:
    """
    Create a TLS syslog server.

    Args:
        host: Host address to bind to
        port: Port to listen on
        certfile: Path to the server certificate file
        keyfile: Path to the server private key file
        ca_certs: Path to the CA certificates file for client verification
        verify_client: Whether to verify client certificates
        min_version: Minimum TLS version to accept (default: TLS 1.3)
        ciphers: Optional cipher string to restrict allowed ciphers
        framing_mode: The framing mode to use
        end_of_message_marker: The marker indicating end of message for non-transparent framing
        max_message_length: Maximum message length for non-transparent framing
        decoder_type: The type of syslog decoder to use
        cert_rules: Optional list of certificate verification rules
        enable_model_json_output: Whether to generate JSON output of decoded models (for demos/debugging)

    Returns:
        Tuple of (server, ssl_context)
    """
    # Create SSL context and certificate verifier
    ssl_context, cert_verifier = TLSContextBuilder.create_server_context(
        certfile=certfile,
        keyfile=keyfile,
        ca_certs=ca_certs,
        verify_client=verify_client,
        min_version=min_version,
        ciphers=ciphers,
        cert_rules=cert_rules,
    )

    # Create the server
    server = await asyncio.start_server(
        lambda r, w: None,  # Placeholder, will be replaced by protocol factory
        host,
        port,
        ssl=ssl_context,
        protocol_factory=lambda: SyslogTLSProtocol(
            framing_mode=framing_mode,
            end_of_message_marker=end_of_message_marker,
            max_message_length=max_message_length,
            decoder_type=decoder_type,
            cert_verifier=cert_verifier,
            enable_model_json_output=enable_model_json_output,
        ),
    )

    return server, ssl_context
