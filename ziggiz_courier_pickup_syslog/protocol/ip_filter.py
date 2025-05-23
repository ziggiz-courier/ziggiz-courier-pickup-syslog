# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# IP filtering utilities for syslog server

# Standard library imports
import ipaddress
import logging

from typing import List, Optional


class IPFilter:
    """
    IP filtering utility for checking if an IP address is allowed.
    """

    def __init__(self, allowed_ips: Optional[List[str]] = None):
        """
        Initialize the IP filter.

        Args:
            allowed_ips: List of allowed IP addresses or networks in CIDR notation.
                         If empty or None, all IPs are allowed.
        """
        self.logger = logging.getLogger(
            "ziggiz_courier_pickup_syslog.protocol.ip_filter"
        )
        self.allowed_networks = []

        # If no allowed IPs are specified, allow all
        if not allowed_ips:
            self.allow_all = True
            return

        self.allow_all = False

        # Parse the allowed IPs into network objects
        for ip_str in allowed_ips:
            try:
                # Handle both individual IPs and networks
                if "/" in ip_str:
                    network = ipaddress.ip_network(ip_str, strict=False)
                else:
                    # Convert single IP to a /32 or /128 network
                    ip = ipaddress.ip_address(ip_str)
                    if ip.version == 4:
                        network = ipaddress.IPv4Network(f"{ip_str}/32", strict=False)
                    else:
                        network = ipaddress.IPv6Network(f"{ip_str}/128", strict=False)

                self.allowed_networks.append(network)
                self.logger.debug("Added allowed network", extra={"network": network})
            except ValueError as e:
                self.logger.warning(
                    "Invalid IP address or network", extra={"ip": ip_str, "error": e}
                )

    def is_allowed(self, ip_str: str) -> bool:
        """
        Check if an IP address is allowed.

        Args:
            ip_str: The IP address to check

        Returns:
            True if the IP is allowed, False otherwise
        """
        # If no allowed IPs are specified, allow all
        if self.allow_all:
            return True

        # If the IP string is invalid, deny it
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            self.logger.warning("Invalid IP address", extra={"ip": ip_str})
            return False

        # Check if the IP is in any of the allowed networks
        for network in self.allowed_networks:
            if ip.version == network.version and ip in network:
                return True

        return False
