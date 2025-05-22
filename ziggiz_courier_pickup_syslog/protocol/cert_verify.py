# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Certificate verification helpers for TLS connections

# Standard library imports
import logging
import re
import ssl

from typing import Dict, List, Optional, Union


class CertificateRule:
    """
    A rule for verifying certificate attributes.

    This class represents a rule that can be used to verify attributes
    in a client certificate, such as the Common Name (CN) or Organizational Unit (OU).
    """

    def __init__(
        self,
        attribute: str,
        pattern: str,
        required: bool = True,
    ):
        """
        Initialize a certificate verification rule.

        Args:
            attribute: The certificate attribute to check (e.g., "CN", "OU")
            pattern: The regex pattern to match against the attribute value
            required: Whether this attribute is required to be present
        """
        self.attribute = attribute
        self.pattern_str = pattern
        self.required = required

        # Compile the regex pattern
        try:
            self.pattern = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{pattern}': {e}")

    def __repr__(self) -> str:
        """Return a string representation of the rule."""
        return (
            f"CertificateRule(attribute='{self.attribute}', "
            f"pattern='{self.pattern_str}', required={self.required})"
        )


class CertificateVerifier:
    """
    Helper class for verifying client certificates against a set of rules.

    This class provides methods to verify that a client certificate's
    attributes match a set of predefined rules.
    """

    def __init__(self, rules: Optional[List[CertificateRule]] = None):
        """
        Initialize the certificate verifier.

        Args:
            rules: A list of certificate verification rules
        """
        self.logger = logging.getLogger(
            "ziggiz_courier_pickup_syslog.protocol.cert_verify"
        )
        self.rules = rules or []

    def add_rule(self, rule: CertificateRule) -> None:
        """
        Add a rule to the verifier.

        Args:
            rule: The rule to add
        """
        self.rules.append(rule)

    def extract_cert_attributes(self, cert: ssl.SSLObject) -> Dict[str, str]:
        """
        Extract attributes from a certificate.

        Args:
            cert: The SSL certificate object

        Returns:
            A dictionary of certificate attributes
        """
        attributes = {}

        # Get the subject from the certificate
        subject = cert.get_subject()
        if subject:
            # Parse the subject DN into components
            for key, value in subject.get_components():
                # Convert bytes to string if needed
                key_str = key.decode("utf-8") if isinstance(key, bytes) else key
                value_str = value.decode("utf-8") if isinstance(value, bytes) else value
                attributes[key_str] = value_str

        return attributes

    def verify_certificate(self, cert: ssl.SSLObject) -> bool:
        """
        Verify a certificate against the configured rules.

        Args:
            cert: The SSL certificate object

        Returns:
            True if the certificate passes all rules, False otherwise
        """
        if not self.rules:
            self.logger.warning("No certificate verification rules configured")
            return True

        # Extract certificate attributes
        attributes = self.extract_cert_attributes(cert)
        self.logger.debug(f"Certificate attributes: {attributes}")

        # Check each rule
        for rule in self.rules:
            attribute_value = attributes.get(rule.attribute)

            # Check if the attribute is present
            if attribute_value is None:
                if rule.required:
                    self.logger.warning(
                        f"Required attribute '{rule.attribute}' not found in certificate"
                    )
                    return False
                else:
                    # Attribute is not required, so skip this rule
                    continue

            # Check if the attribute matches the pattern
            if not rule.pattern.match(attribute_value):
                self.logger.warning(
                    f"Attribute '{rule.attribute}' with value '{attribute_value}' "
                    f"does not match pattern '{rule.pattern_str}'"
                )
                return False

        # All rules passed
        return True


def create_verifier_from_config(
    rules_config: List[Dict[str, Union[str, bool]]],
) -> CertificateVerifier:
    """
    Create a certificate verifier from a configuration dictionary.

    Args:
        rules_config: A list of rule configurations, where each rule is a dictionary
                     with 'attribute', 'pattern', and optional 'required' keys

    Returns:
        A configured CertificateVerifier

    Raises:
        ValueError: If the configuration is invalid
    """
    verifier = CertificateVerifier()

    for rule_config in rules_config:
        # Extract rule parameters
        attribute = rule_config.get("attribute")
        pattern = rule_config.get("pattern")
        required = rule_config.get("required", True)

        # Validate parameters
        if not attribute:
            raise ValueError("Certificate rule must specify an 'attribute'")
        if not pattern:
            raise ValueError("Certificate rule must specify a 'pattern'")

        # Create and add the rule
        rule = CertificateRule(
            attribute=attribute,
            pattern=pattern,
            required=required,
        )
        verifier.add_rule(rule)

    return verifier
