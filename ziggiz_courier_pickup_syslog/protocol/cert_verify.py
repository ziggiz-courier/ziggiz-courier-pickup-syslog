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

from typing import Any, Dict, List, Optional


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

    def extract_cert_attributes(self, cert: Any) -> Dict[str, str]:
        """
        Extract attributes from a certificate.

        Args:
            cert: The SSL certificate object or dictionary

        Returns:
            A dictionary of certificate attributes
        """
        attributes = {}

        # Handle mock objects used in tests
        if hasattr(cert, "get_subject"):
            subject = cert.get_subject()
            if subject and hasattr(subject, "get_components"):
                for key, value in subject.get_components():
                    # Convert bytes to string if needed
                    key_str = key.decode("utf-8") if isinstance(key, bytes) else key
                    value_str = (
                        value.decode("utf-8") if isinstance(value, bytes) else value
                    )
                    attributes[key_str] = value_str
            return attributes

        # Handle dictionary certificate as returned by getpeercert()
        if isinstance(cert, dict):
            subject = cert.get("subject", [])
            if subject:
                for component in subject:
                    for name_value in component:
                        if len(name_value) >= 2:
                            name, value = name_value
                            attributes[name] = value

        return attributes

    def verify_certificate(self, ssl_obj: Any) -> bool:
        """
        Verify a certificate against the configured rules.

        Args:
            ssl_obj: The SSL object, could be an SSLObject, certificate dict, or a mock

        Returns:
            True if the certificate passes all rules, False otherwise
        """
        if not self.rules:
            self.logger.warning("No certificate verification rules configured")
            return True

        # Extract certificate attributes directly
        attributes = self.extract_cert_attributes(ssl_obj)
        self.logger.debug("Certificate attributes", extra={"attributes": attributes})

        # Check each rule
        for rule in self.rules:
            attribute_value = attributes.get(rule.attribute)

            # Check if the attribute is present
            if attribute_value is None:
                if rule.required:
                    self.logger.warning(
                        "Required attribute not found in certificate",
                        extra={"attribute": rule.attribute},
                    )
                    return False
                else:
                    # Attribute is not required, so skip this rule
                    continue

            # Check if the attribute matches the pattern
            if not rule.pattern.match(attribute_value):
                self.logger.warning(
                    "Attribute with value does not match pattern",
                    extra={
                        "attribute": rule.attribute,
                        "value": attribute_value,
                        "pattern": rule.pattern_str,
                    },
                )
                return False

        # All rules passed
        return True


def create_verifier_from_config(
    rules_config: List[Dict[str, Any]],
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
        if not attribute or not isinstance(attribute, str):
            raise ValueError("Certificate rule must specify an 'attribute' as a string")
        if not pattern or not isinstance(pattern, str):
            raise ValueError("Certificate rule must specify a 'pattern' as a string")

        # Ensure required is a boolean
        if not isinstance(required, bool):
            required = bool(required)

        # Create and add the rule
        rule = CertificateRule(
            attribute=attribute,
            pattern=pattern,
            required=required,
        )
        verifier.add_rule(rule)

    return verifier
