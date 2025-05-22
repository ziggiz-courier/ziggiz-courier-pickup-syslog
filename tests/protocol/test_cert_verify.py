# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the certificate verification implementation

# Standard library imports
import re

from unittest.mock import MagicMock

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.cert_verify import (
    CertificateRule,
    CertificateVerifier,
    create_verifier_from_config,
)


class TestCertificateRule:
    """Tests for the CertificateRule class."""

    @pytest.mark.unit
    def test_init(self):
        """Test initialization of the rule."""
        rule = CertificateRule(attribute="CN", pattern="test.*", required=True)

        assert rule.attribute == "CN"
        assert rule.pattern_str == "test.*"
        assert rule.required is True
        assert isinstance(rule.pattern, re.Pattern)

    @pytest.mark.unit
    def test_init_with_invalid_pattern(self):
        """Test initialization with an invalid regex pattern."""
        with pytest.raises(ValueError) as excinfo:
            CertificateRule(attribute="CN", pattern="test[", required=True)

        assert "Invalid regex pattern" in str(excinfo.value)

    @pytest.mark.unit
    def test_repr(self):
        """Test string representation of the rule."""
        rule = CertificateRule(attribute="CN", pattern="test.*", required=False)

        assert "CertificateRule" in repr(rule)
        assert "attribute='CN'" in repr(rule)
        assert "pattern='test.*'" in repr(rule)
        assert "required=False" in repr(rule)


class TestCertificateVerifier:
    """Tests for the CertificateVerifier class."""

    @pytest.mark.unit
    def test_init(self):
        """Test initialization of the verifier."""
        verifier = CertificateVerifier()

        assert verifier.rules == []
        assert (
            verifier.logger.name == "ziggiz_courier_pickup_syslog.protocol.cert_verify"
        )

    @pytest.mark.unit
    def test_add_rule(self):
        """Test adding a rule to the verifier."""
        verifier = CertificateVerifier()
        rule = CertificateRule(attribute="CN", pattern="test.*", required=True)

        verifier.add_rule(rule)

        assert len(verifier.rules) == 1
        assert verifier.rules[0] is rule

    @pytest.mark.unit
    def test_extract_cert_attributes(self):
        """Test extracting attributes from a certificate."""
        verifier = CertificateVerifier()

        # Create a mock certificate with subject components
        mock_cert = MagicMock()
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [
            (b"CN", b"test.example.com"),
            (b"OU", b"TestOU"),
            (b"O", b"Test Organization"),
        ]
        mock_cert.get_subject.return_value = mock_subject

        # Extract attributes
        attributes = verifier.extract_cert_attributes(mock_cert)

        # Check that attributes were correctly extracted and decoded
        assert attributes["CN"] == "test.example.com"
        assert attributes["OU"] == "TestOU"
        assert attributes["O"] == "Test Organization"

    @pytest.mark.unit
    def test_verify_certificate_no_rules(self):
        """Test verifying a certificate with no rules."""
        verifier = CertificateVerifier()
        mock_cert = MagicMock()

        # Verification should pass if there are no rules
        assert verifier.verify_certificate(mock_cert) is True

    @pytest.mark.unit
    def test_verify_certificate_missing_required_attribute(self):
        """Test verifying a certificate with a missing required attribute."""
        verifier = CertificateVerifier()
        rule = CertificateRule(attribute="CN", pattern="test.*", required=True)
        verifier.add_rule(rule)

        # Create a mock certificate with no CN attribute
        mock_cert = MagicMock()
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [
            (b"OU", b"TestOU"),
        ]
        mock_cert.get_subject.return_value = mock_subject

        # Verification should fail because CN is required but missing
        assert verifier.verify_certificate(mock_cert) is False

    @pytest.mark.unit
    def test_verify_certificate_missing_optional_attribute(self):
        """Test verifying a certificate with a missing optional attribute."""
        verifier = CertificateVerifier()
        rule = CertificateRule(attribute="OU", pattern="Test.*", required=False)
        verifier.add_rule(rule)

        # Create a mock certificate with no OU attribute
        mock_cert = MagicMock()
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [
            (b"CN", b"test.example.com"),
        ]
        mock_cert.get_subject.return_value = mock_subject

        # Verification should pass because OU is optional
        assert verifier.verify_certificate(mock_cert) is True

    @pytest.mark.unit
    def test_verify_certificate_matching_pattern(self):
        """Test verifying a certificate with an attribute matching the pattern."""
        verifier = CertificateVerifier()
        rule = CertificateRule(attribute="CN", pattern="test.*\\.com", required=True)
        verifier.add_rule(rule)

        # Create a mock certificate with a matching CN
        mock_cert = MagicMock()
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [
            (b"CN", b"test.example.com"),
        ]
        mock_cert.get_subject.return_value = mock_subject

        # Verification should pass because CN matches the pattern
        assert verifier.verify_certificate(mock_cert) is True

    @pytest.mark.unit
    def test_verify_certificate_non_matching_pattern(self):
        """Test verifying a certificate with an attribute not matching the pattern."""
        verifier = CertificateVerifier()
        rule = CertificateRule(attribute="CN", pattern="prod.*\\.com", required=True)
        verifier.add_rule(rule)

        # Create a mock certificate with a non-matching CN
        mock_cert = MagicMock()
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [
            (b"CN", b"test.example.com"),
        ]
        mock_cert.get_subject.return_value = mock_subject

        # Verification should fail because CN doesn't match the pattern
        assert verifier.verify_certificate(mock_cert) is False

    @pytest.mark.unit
    def test_verify_certificate_multiple_rules(self):
        """Test verifying a certificate with multiple rules."""
        verifier = CertificateVerifier()
        rule1 = CertificateRule(attribute="CN", pattern="test.*\\.com", required=True)
        rule2 = CertificateRule(attribute="OU", pattern="Test.*", required=True)
        verifier.add_rule(rule1)
        verifier.add_rule(rule2)

        # Create a mock certificate with matching attributes
        mock_cert = MagicMock()
        mock_subject = MagicMock()
        mock_subject.get_components.return_value = [
            (b"CN", b"test.example.com"),
            (b"OU", b"TestOU"),
        ]
        mock_cert.get_subject.return_value = mock_subject

        # Verification should pass because both attributes match their patterns
        assert verifier.verify_certificate(mock_cert) is True


@pytest.mark.unit
def test_create_verifier_from_config():
    """Test creating a verifier from a configuration dictionary."""
    config = [
        {"attribute": "CN", "pattern": "test.*\\.com", "required": True},
        {"attribute": "OU", "pattern": "Test.*", "required": False},
    ]

    verifier = create_verifier_from_config(config)

    assert len(verifier.rules) == 2
    assert verifier.rules[0].attribute == "CN"
    assert verifier.rules[0].pattern_str == "test.*\\.com"
    assert verifier.rules[0].required is True
    assert verifier.rules[1].attribute == "OU"
    assert verifier.rules[1].pattern_str == "Test.*"
    assert verifier.rules[1].required is False


@pytest.mark.unit
def test_create_verifier_from_config_missing_attribute():
    """Test creating a verifier with a missing attribute in the config."""
    config = [
        {"pattern": "test.*\\.com", "required": True},
    ]

    with pytest.raises(ValueError) as excinfo:
        create_verifier_from_config(config)

    assert "must specify an 'attribute'" in str(excinfo.value)


@pytest.mark.unit
def test_create_verifier_from_config_missing_pattern():
    """Test creating a verifier with a missing pattern in the config."""
    config = [
        {"attribute": "CN", "required": True},
    ]

    with pytest.raises(ValueError) as excinfo:
        create_verifier_from_config(config)

    assert "must specify a 'pattern'" in str(excinfo.value)
