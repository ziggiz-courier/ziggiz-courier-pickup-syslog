# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the TLS protocol implementation

# NOTE: THESE TESTS MAY BE OUTDATED
# The base protocol implementation has been refactored. Base functionality is now
# tested in test_base_stream_protocol.py and test_base_stream_extended.py.
#
# Since TLS extends TCP protocol, many of the same considerations apply.
# This file should be updated to focus on TLS-specific functionality like certificate
# verification and TLS-specific connection handling.

# Standard library imports
import logging
import ssl

from unittest.mock import MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.tls import (
    SyslogTLSProtocol,
    TLSContextBuilder,
    create_tls_server,
)


class TestSyslogTLSProtocol:
    """Tests for the SyslogTLSProtocol class."""

    @pytest.mark.unit
    def test_init(self):
        """Test initialization of the protocol."""
        protocol = SyslogTLSProtocol()

        # Check that the logger is properly initialized
        assert protocol.logger.name == "ziggiz_courier_pickup_syslog.protocol.tls"
        assert protocol.transport is None
        assert protocol.decoder_type == "auto"
        assert isinstance(protocol.connection_cache, dict)
        assert isinstance(protocol.event_parsing_cache, dict)

    @pytest.mark.unit
    def test_connection_made_with_ssl(self, caplog):
        """Test connection_made method with SSL information."""
        caplog.set_level(logging.DEBUG)
        protocol = SyslogTLSProtocol()

        # Create a mock transport with SSL information
        mock_transport = MagicMock()
        mock_transport.get_extra_info.side_effect = lambda key: {
            "peername": ("192.168.1.1", 12345),
            "ssl_object": MagicMock(
                cipher=lambda: ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                version=lambda: "TLSv1.3",
            ),
        }.get(key)

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport and peername are set
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)
        # Functional: verify state
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)

    @pytest.mark.unit
    def test_connection_made_without_ssl(self, caplog):
        """Test connection_made method without SSL information."""
        caplog.set_level(logging.WARNING)
        protocol = SyslogTLSProtocol()

        # Create a mock transport without SSL information
        mock_transport = MagicMock()
        mock_transport.get_extra_info.side_effect = lambda key: {
            "peername": ("192.168.1.1", 12345),
            "ssl_object": None,
        }.get(key)

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check the transport and peername are set
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)
        # Functional: verify state
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)


class TestTLSContextBuilder:
    """Tests for the TLSContextBuilder class."""

    @pytest.mark.unit
    def test_create_server_context(self):
        """Test creating a server SSL context."""
        # Create a mock context
        mock_context = MagicMock()

        # Patch the ssl.create_default_context function
        with patch(
            "ssl.create_default_context", return_value=mock_context
        ) as mock_create_context:
            # Patch the load_cert_chain method on the mock context
            mock_context.load_cert_chain = MagicMock()

            # Call the function under test
            context, cert_verifier = TLSContextBuilder.create_server_context(
                certfile="cert.pem",
                keyfile="key.pem",
            )

            # Check that the context was created correctly
            mock_create_context.assert_called_once_with(ssl.Purpose.CLIENT_AUTH)
            mock_context.load_cert_chain.assert_called_once_with(
                certfile="cert.pem", keyfile="key.pem"
            )
            assert context.minimum_version == ssl.TLSVersion.TLSv1_3
            assert cert_verifier is None

    @pytest.mark.unit
    def test_create_server_context_with_client_verification(self):
        """Test creating a server SSL context with client verification."""
        # Create a mock context
        mock_context = MagicMock()

        # Patch the ssl.create_default_context function
        with patch(
            "ssl.create_default_context", return_value=mock_context
        ) as mock_create_context:
            # Patch the methods on the mock context
            mock_context.load_cert_chain = MagicMock()
            mock_context.load_verify_locations = MagicMock()

            # Call the function under test
            context, cert_verifier = TLSContextBuilder.create_server_context(
                certfile="cert.pem",
                keyfile="key.pem",
                ca_certs="ca.pem",
                verify_client=True,
            )

            # Check that the context was created correctly
            mock_create_context.assert_called_once_with(ssl.Purpose.CLIENT_AUTH)
            mock_context.load_cert_chain.assert_called_once_with(
                certfile="cert.pem", keyfile="key.pem"
            )
            mock_context.load_verify_locations.assert_called_once_with(cafile="ca.pem")
            assert context.verify_mode == ssl.CERT_REQUIRED
            assert cert_verifier is None

    @pytest.mark.unit
    def test_create_server_context_with_custom_settings(self):
        """Test creating a server SSL context with custom settings."""
        # Create a mock context
        mock_context = MagicMock()

        # Patch the ssl.create_default_context function
        with patch(
            "ssl.create_default_context", return_value=mock_context
        ) as mock_create_context:
            # Patch the methods on the mock context
            mock_context.load_cert_chain = MagicMock()
            mock_context.set_ciphers = MagicMock()

            # Call the function under test
            context, cert_verifier = TLSContextBuilder.create_server_context(
                certfile="cert.pem",
                keyfile="key.pem",
                min_version=ssl.TLSVersion.TLSv1_2,
                ciphers="HIGH:!aNULL:!MD5",
            )

            # Check that the context was created correctly
            mock_create_context.assert_called_once_with(ssl.Purpose.CLIENT_AUTH)
            mock_context.load_cert_chain.assert_called_once_with(
                certfile="cert.pem", keyfile="key.pem"
            )
            mock_context.set_ciphers.assert_called_once_with("HIGH:!aNULL:!MD5")
            assert context.minimum_version == ssl.TLSVersion.TLSv1_2
            assert cert_verifier is None

    @pytest.mark.unit
    def test_create_server_context_missing_ca_certs(self):
        """Test creating a server SSL context with client verification but missing CA certs."""
        # Mock the ssl.create_default_context function to avoid file not found errors
        mock_context = MagicMock()
        with patch("ssl.create_default_context", return_value=mock_context):
            mock_context.load_cert_chain = MagicMock()

            # Call the function under test and expect an error
            with pytest.raises(ValueError) as excinfo:
                TLSContextBuilder.create_server_context(
                    certfile="cert.pem",
                    keyfile="key.pem",
                    verify_client=True,
                )

            # Check that the correct error is raised
            assert "CA certificates file must be provided" in str(excinfo.value)


@pytest.mark.asyncio
async def test_create_tls_server():
    """Test creating a TLS server."""
    # Mock the TLSContextBuilder.create_server_context method
    mock_ssl_context = MagicMock()
    mock_cert_verifier = MagicMock()

    with patch(
        "ziggiz_courier_pickup_syslog.protocol.tls.TLSContextBuilder.create_server_context",
        return_value=(mock_ssl_context, mock_cert_verifier),
    ) as mock_create_context:

        # Mock asyncio.start_server
        mock_server = MagicMock()

        # Mock the protocol class
        with patch(
            "asyncio.start_server", return_value=mock_server
        ) as mock_start_server:
            # Call the function under test
            server, ssl_context = await create_tls_server(
                host="127.0.0.1",
                port=6514,
                certfile="cert.pem",
                keyfile="key.pem",
                ca_certs="ca.pem",
                verify_client=True,
                framing_mode="non_transparent",
                decoder_type="rfc5424",
            )

            # Check that the context was created with the correct parameters
            mock_create_context.assert_called_once_with(
                certfile="cert.pem",
                keyfile="key.pem",
                ca_certs="ca.pem",
                verify_client=True,
                min_version=ssl.TLSVersion.TLSv1_3,
                ciphers=None,
                cert_rules=None,
            )

            # Check that start_server was called
            mock_start_server.assert_called_once()

            # Check that the server and context are returned
            assert server == mock_server
            assert ssl_context == mock_ssl_context
