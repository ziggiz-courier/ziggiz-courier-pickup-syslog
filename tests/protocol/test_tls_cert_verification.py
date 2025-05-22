# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for TLS certificate verification in the TLS protocol

# Standard library imports
import logging
import ssl

from unittest.mock import MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.config import CertificateRuleConfig, Config
from ziggiz_courier_pickup_syslog.protocol.cert_verify import (
    CertificateRule,
    CertificateVerifier,
)
from ziggiz_courier_pickup_syslog.protocol.tls import (
    SyslogTLSProtocol,
    TLSContextBuilder,
)


class TestTLSContextBuilderWithCertRules:
    """Tests for the TLSContextBuilder class with certificate rules."""

    @pytest.mark.unit
    def test_create_server_context_with_cert_rules(self):
        """Test creating a server SSL context with certificate verification rules."""
        # Create a mock context
        mock_context = MagicMock()

        # Patch the ssl.create_default_context function
        with patch(
            "ssl.create_default_context", return_value=mock_context
        ) as mock_create_context:
            # Patch the methods on the mock context
            mock_context.load_cert_chain = MagicMock()
            mock_context.load_verify_locations = MagicMock()

            # Create certificate rules
            cert_rules = [
                {
                    "attribute": "CN",
                    "pattern": "client.*\\.example\\.com",
                    "required": True,
                },
                {"attribute": "OU", "pattern": "DevOps", "required": False},
            ]

            # Call the function under test
            context, verifier = TLSContextBuilder.create_server_context(
                certfile="cert.pem",
                keyfile="key.pem",
                ca_certs="ca.pem",
                verify_client=True,
                cert_rules=cert_rules,
            )

            # Check that the context was created correctly
            mock_create_context.assert_called_once_with(ssl.Purpose.CLIENT_AUTH)
            mock_context.load_cert_chain.assert_called_once_with(
                certfile="cert.pem", keyfile="key.pem"
            )
            mock_context.load_verify_locations.assert_called_once_with(cafile="ca.pem")
            assert context.verify_mode == ssl.CERT_REQUIRED

            # Check that the verifier was created correctly
            assert verifier is not None
            assert len(verifier.rules) == 2
            assert verifier.rules[0].attribute == "CN"
            assert verifier.rules[0].pattern_str == "client.*\\.example\\.com"
            assert verifier.rules[0].required is True
            assert verifier.rules[1].attribute == "OU"
            assert verifier.rules[1].pattern_str == "DevOps"
            assert verifier.rules[1].required is False

    @pytest.mark.unit
    def test_create_server_context_without_cert_rules(self):
        """Test creating a server SSL context without certificate verification rules."""
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
            context, verifier = TLSContextBuilder.create_server_context(
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

            # Check that no verifier was created
            assert verifier is None


class TestSyslogTLSProtocolWithCertVerification:
    """Tests for the SyslogTLSProtocol class with certificate verification."""

    @pytest.mark.unit
    def test_connection_made_with_valid_client_cert(self, caplog):
        """Test connection_made method with a valid client certificate."""
        caplog.set_level(logging.INFO)

        # Create a certificate verifier with a rule
        verifier = CertificateVerifier()
        verifier.add_rule(
            CertificateRule(attribute="CN", pattern="client.*", required=True)
        )

        # Create the protocol with the verifier
        protocol = SyslogTLSProtocol(cert_verifier=verifier)

        # Create a mock SSL object with a certificate
        mock_ssl_object = MagicMock()
        mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_object.version.return_value = "TLSv1.3"

        # Mock the certificate verification to return True
        verifier.verify_certificate = MagicMock(return_value=True)

        # Mock the getpeercert method to return a certificate
        mock_ssl_object.getpeercert.return_value = {
            "subject": [(("CN", "client.example.com"),)],
            "issuer": [(("CN", "Test CA"),)],
            "notBefore": "Jan 1 00:00:00 2023 GMT",
            "notAfter": "Dec 31 23:59:59 2023 GMT",
        }

        # Create a mock transport with the SSL object
        mock_transport = MagicMock()
        mock_transport.get_extra_info.side_effect = lambda key: {
            "peername": ("192.168.1.1", 12345),
            "ssl_object": mock_ssl_object,
        }.get(key)

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check that the transport and peername are set
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)

        # Check that the certificate verification was called
        verifier.verify_certificate.assert_called_once_with(mock_ssl_object)

        # Check log messages
        assert "TLS connection established from 192.168.1.1:12345" in caplog.text
        assert "Client certificate from 192.168.1.1:12345" in caplog.text
        assert "Subject: CN=client.example.com" in caplog.text
        assert "Issuer: CN=Test CA" in caplog.text
        assert (
            "Valid from Jan 1 00:00:00 2023 GMT to Dec 31 23:59:59 2023 GMT"
            in caplog.text
        )

        # Check that no warning about failed verification was logged
        assert "failed attribute verification" not in caplog.text

    @pytest.mark.unit
    def test_connection_made_with_invalid_client_cert(self, caplog):
        """Test connection_made method with an invalid client certificate."""
        caplog.set_level(logging.WARNING)

        # Create a certificate verifier with a rule
        verifier = CertificateVerifier()
        verifier.add_rule(
            CertificateRule(attribute="CN", pattern="prod.*", required=True)
        )

        # Create the protocol with the verifier
        protocol = SyslogTLSProtocol(cert_verifier=verifier)

        # Create a mock SSL object with a certificate
        mock_ssl_object = MagicMock()
        mock_ssl_object.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssl_object.version.return_value = "TLSv1.3"

        # Mock the certificate verification to return False
        verifier.verify_certificate = MagicMock(return_value=False)

        # Mock the getpeercert method to return a certificate
        mock_ssl_object.getpeercert.return_value = {
            "subject": [(("CN", "client.example.com"),)],
            "issuer": [(("CN", "Test CA"),)],
            "notBefore": "Jan 1 00:00:00 2023 GMT",
            "notAfter": "Dec 31 23:59:59 2023 GMT",
        }

        # Create a mock transport with the SSL object
        mock_transport = MagicMock()
        mock_transport.get_extra_info.side_effect = lambda key: {
            "peername": ("192.168.1.1", 12345),
            "ssl_object": mock_ssl_object,
        }.get(key)

        # Call connection_made
        protocol.connection_made(mock_transport)

        # Check that the transport and peername are set
        assert protocol.transport == mock_transport
        assert protocol.peername == ("192.168.1.1", 12345)

        # Check that the certificate verification was called
        verifier.verify_certificate.assert_called_once_with(mock_ssl_object)

        # Check log messages - only check for the warning about failed verification
        # since we're only capturing WARNING level logs
        assert (
            "Client certificate from 192.168.1.1:12345 failed attribute verification"
            in caplog.text
        )


@pytest.mark.unit
def test_config_with_cert_rules():
    """Test the Config class with certificate rules."""
    # Create a config with certificate rules
    config = Config(
        protocol="tls",
        tls_certfile="cert.pem",
        tls_keyfile="key.pem",
        tls_ca_certs="ca.pem",
        tls_verify_client=True,
        tls_cert_rules=[
            CertificateRuleConfig(
                attribute="CN",
                pattern="client.*\\.example\\.com",
                required=True,
            ),
            CertificateRuleConfig(
                attribute="OU",
                pattern="DevOps",
                required=False,
            ),
        ],
    )

    # Check that the config was created correctly
    assert config.protocol == "tls"
    assert config.tls_certfile == "cert.pem"
    assert config.tls_keyfile == "key.pem"
    assert config.tls_ca_certs == "ca.pem"
    assert config.tls_verify_client is True
    assert len(config.tls_cert_rules) == 2
    assert config.tls_cert_rules[0].attribute == "CN"
    assert config.tls_cert_rules[0].pattern == "client.*\\.example\\.com"
    assert config.tls_cert_rules[0].required is True
    assert config.tls_cert_rules[1].attribute == "OU"
    assert config.tls_cert_rules[1].pattern == "DevOps"
    assert config.tls_cert_rules[1].required is False


@pytest.mark.unit
def test_config_with_cert_rules_without_verification():
    """Test the Config class with certificate rules but without client verification."""
    # Create a config with certificate rules but without client verification
    with pytest.raises(ValueError) as excinfo:
        Config(
            protocol="tls",
            tls_certfile="cert.pem",
            tls_keyfile="key.pem",
            tls_verify_client=False,  # Client verification is disabled
            tls_cert_rules=[
                CertificateRuleConfig(
                    attribute="CN",
                    pattern="client.*\\.example\\.com",
                    required=True,
                ),
            ],
        )

    # Check that the correct error is raised
    assert (
        "Certificate rules can only be used when client verification is enabled"
        in str(excinfo.value)
    )
