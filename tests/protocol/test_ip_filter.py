# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for IP filtering functionality

# Standard library imports
import unittest

from unittest.mock import MagicMock, patch

# Local/package imports
# Local imports
from ziggiz_courier_pickup_syslog.protocol.ip_filter import IPFilter


class TestIPFilter(unittest.TestCase):
    """Test cases for the IPFilter class."""

    def test_init_empty_list(self):
        """Test initialization with an empty list."""
        ip_filter = IPFilter([])
        self.assertTrue(ip_filter.allow_all)
        self.assertEqual(len(ip_filter.allowed_networks), 0)

    def test_init_none(self):
        """Test initialization with None."""
        ip_filter = IPFilter(None)
        self.assertTrue(ip_filter.allow_all)
        self.assertEqual(len(ip_filter.allowed_networks), 0)

    def test_init_with_ips(self):
        """Test initialization with a list of IPs."""
        ip_filter = IPFilter(["192.168.1.1", "10.0.0.0/24", "2001:db8::/64"])
        self.assertFalse(ip_filter.allow_all)
        self.assertEqual(len(ip_filter.allowed_networks), 3)

    def test_init_with_invalid_ip(self):
        """Test initialization with an invalid IP."""
        with patch("logging.Logger.warning") as mock_warning:
            ip_filter = IPFilter(["192.168.1.1", "invalid_ip", "10.0.0.0/24"])
            self.assertFalse(ip_filter.allow_all)
            self.assertEqual(len(ip_filter.allowed_networks), 2)
            mock_warning.assert_called_once()

    def test_is_allowed_allow_all(self):
        """Test is_allowed when all IPs are allowed."""
        ip_filter = IPFilter([])
        self.assertTrue(ip_filter.is_allowed("192.168.1.1"))
        self.assertTrue(ip_filter.is_allowed("10.0.0.1"))
        self.assertTrue(ip_filter.is_allowed("2001:db8::1"))

    def test_is_allowed_specific_ip(self):
        """Test is_allowed with specific IPs."""
        ip_filter = IPFilter(["192.168.1.1", "10.0.0.0/24"])
        self.assertTrue(ip_filter.is_allowed("192.168.1.1"))
        self.assertTrue(ip_filter.is_allowed("10.0.0.1"))
        self.assertFalse(ip_filter.is_allowed("192.168.1.2"))
        self.assertFalse(ip_filter.is_allowed("10.0.1.1"))

    def test_is_allowed_ipv6(self):
        """Test is_allowed with IPv6 addresses."""
        ip_filter = IPFilter(["2001:db8::/64", "::1"])
        self.assertTrue(ip_filter.is_allowed("2001:db8::1"))
        self.assertTrue(ip_filter.is_allowed("::1"))
        self.assertFalse(ip_filter.is_allowed("2001:db9::1"))

    def test_is_allowed_mixed_ip_versions(self):
        """Test is_allowed with mixed IP versions."""
        ip_filter = IPFilter(["192.168.1.0/24", "2001:db8::/64"])
        self.assertTrue(ip_filter.is_allowed("192.168.1.1"))
        self.assertTrue(ip_filter.is_allowed("2001:db8::1"))
        self.assertFalse(ip_filter.is_allowed("10.0.0.1"))
        self.assertFalse(ip_filter.is_allowed("2001:db9::1"))

    def test_is_allowed_invalid_ip(self):
        """Test is_allowed with an invalid IP."""
        ip_filter = IPFilter(["192.168.1.0/24"])
        with patch("logging.Logger.warning") as mock_warning:
            self.assertFalse(ip_filter.is_allowed("invalid_ip"))
            mock_warning.assert_called_once()


class TestTCPProtocolIPFiltering(unittest.TestCase):
    """Test cases for IP filtering in the TCP protocol."""

    def setUp(self):
        """Set up the test case."""
        self.patcher = patch("ziggiz_courier_pickup_syslog.protocol.tcp.IPFilter")
        self.mock_ip_filter_class = self.patcher.start()
        self.mock_ip_filter = MagicMock()
        self.mock_ip_filter_class.return_value = self.mock_ip_filter

    def tearDown(self):
        """Tear down the test case."""
        self.patcher.stop()

    def test_tcp_connection_made_allowed_ip(self):
        """Test connection_made with an allowed IP."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol

        # Set up the protocol
        protocol = SyslogTCPProtocol(allowed_ips=["192.168.1.1"], deny_action="drop")

        # Mock the transport
        transport = MagicMock()
        transport.get_extra_info.return_value = ("192.168.1.1", 12345)

        # Set up the IP filter to allow the IP
        self.mock_ip_filter.is_allowed.return_value = True

        # Call connection_made
        with patch("logging.Logger.info") as mock_info:
            protocol.connection_made(transport)

            # Verify that the connection was accepted
            transport.close.assert_not_called()
            mock_info.assert_called_once()
            self.assertIn("TCP connection established", mock_info.call_args[0][0])

    def test_tcp_connection_made_denied_ip_drop(self):
        """Test connection_made with a denied IP and drop action."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol

        # Set up the protocol
        protocol = SyslogTCPProtocol(allowed_ips=["192.168.1.1"], deny_action="drop")

        # Mock the transport
        transport = MagicMock()
        transport.get_extra_info.return_value = ("10.0.0.1", 12345)

        # Set up the IP filter to deny the IP
        self.mock_ip_filter.is_allowed.return_value = False

        # Call connection_made
        with patch("logging.Logger.warning") as mock_warning:
            protocol.connection_made(transport)

            # Verify that the connection was dropped
            transport.close.assert_called_once()
            mock_warning.assert_called_once()
            self.assertIn("Dropped TCP connection", mock_warning.call_args[0][0])

    def test_tcp_connection_made_denied_ip_reject(self):
        """Test connection_made with a denied IP and reject action."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.tcp import SyslogTCPProtocol

        # Set up the protocol
        protocol = SyslogTCPProtocol(allowed_ips=["192.168.1.1"], deny_action="reject")

        # Mock the transport
        transport = MagicMock()
        transport.get_extra_info.return_value = ("10.0.0.1", 12345)

        # Set up the IP filter to deny the IP
        self.mock_ip_filter.is_allowed.return_value = False

        # Call connection_made
        with patch("logging.Logger.warning") as mock_warning:
            protocol.connection_made(transport)

            # Verify that the connection was rejected
            transport.close.assert_called_once()
            mock_warning.assert_called_once()
            self.assertIn("Rejected TCP connection", mock_warning.call_args[0][0])


class TestUDPProtocolIPFiltering(unittest.TestCase):
    """Test cases for IP filtering in the UDP protocol."""

    def setUp(self):
        """Set up the test case."""
        self.patcher = patch("ziggiz_courier_pickup_syslog.protocol.udp.IPFilter")
        self.mock_ip_filter_class = self.patcher.start()
        self.mock_ip_filter = MagicMock()
        self.mock_ip_filter_class.return_value = self.mock_ip_filter

    def tearDown(self):
        """Tear down the test case."""
        self.patcher.stop()

    def test_udp_datagram_received_allowed_ip(self):
        """Test datagram_received with an allowed IP."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol

        # Set up the protocol
        protocol = SyslogUDPProtocol(allowed_ips=["192.168.1.1"], deny_action="drop")
        protocol.transport = MagicMock()

        # Set up the IP filter to allow the IP
        self.mock_ip_filter.is_allowed.return_value = True

        # Call datagram_received
        with patch("logging.Logger.debug") as mock_debug:
            with patch(
                "ziggiz_courier_pickup_syslog.protocol.decoder_factory.DecoderFactory.decode_message"
            ) as mock_decode:
                protocol.datagram_received(b"test message", ("192.168.1.1", 12345))

                # Verify that the datagram was processed
                mock_debug.assert_called_once()
                self.assertIn("Received UDP datagram", mock_debug.call_args[0][0])
                mock_decode.assert_called_once()

    def test_udp_datagram_received_denied_ip_drop(self):
        """Test datagram_received with a denied IP and drop action."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol

        # Set up the protocol
        protocol = SyslogUDPProtocol(allowed_ips=["192.168.1.1"], deny_action="drop")
        protocol.transport = MagicMock()

        # Set up the IP filter to deny the IP
        self.mock_ip_filter.is_allowed.return_value = False

        # Call datagram_received
        with patch("logging.Logger.warning") as mock_warning:
            with patch(
                "ziggiz_courier_pickup_syslog.protocol.decoder_factory.DecoderFactory.decode_message"
            ) as mock_decode:
                protocol.datagram_received(b"test message", ("10.0.0.1", 12345))

                # Verify that the datagram was dropped
                mock_warning.assert_called_once()
                self.assertIn("Dropped UDP datagram", mock_warning.call_args[0][0])
                mock_decode.assert_not_called()

    def test_udp_datagram_received_denied_ip_reject(self):
        """Test datagram_received with a denied IP and reject action."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.udp import SyslogUDPProtocol

        # Set up the protocol
        protocol = SyslogUDPProtocol(allowed_ips=["192.168.1.1"], deny_action="reject")
        protocol.transport = MagicMock()

        # Set up the IP filter to deny the IP
        self.mock_ip_filter.is_allowed.return_value = False

        # Call datagram_received
        with patch("logging.Logger.warning") as mock_warning:
            with patch(
                "ziggiz_courier_pickup_syslog.protocol.decoder_factory.DecoderFactory.decode_message"
            ) as mock_decode:
                protocol.datagram_received(b"test message", ("10.0.0.1", 12345))

                # Verify that the datagram was rejected
                mock_warning.assert_called_once()
                self.assertIn("Rejected UDP datagram", mock_warning.call_args[0][0])
                mock_decode.assert_not_called()


class TestTLSProtocolIPFiltering(unittest.TestCase):
    """Test cases for IP filtering in the TLS protocol."""

    def setUp(self):
        """Set up the test case."""
        self.patcher = patch("ziggiz_courier_pickup_syslog.protocol.tcp.IPFilter")
        self.mock_ip_filter_class = self.patcher.start()
        self.mock_ip_filter = MagicMock()
        self.mock_ip_filter_class.return_value = self.mock_ip_filter

    def tearDown(self):
        """Tear down the test case."""
        self.patcher.stop()

    def test_tls_connection_made_allowed_ip(self):
        """Test connection_made with an allowed IP."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.tls import SyslogTLSProtocol

        # Set up the protocol
        protocol = SyslogTLSProtocol(allowed_ips=["192.168.1.1"], deny_action="drop")

        # Mock the transport and SSL object
        ssl_mock = MagicMock()
        ssl_mock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssl_mock.version.return_value = "TLSv1.3"
        ssl_mock.getpeercert.return_value = None

        transport = MagicMock()
        transport.get_extra_info.side_effect = lambda key: {
            "peername": ("192.168.1.1", 12345),
            "ssl_object": ssl_mock,
        }.get(key)

        # Set up the IP filter to allow the IP
        self.mock_ip_filter.is_allowed.return_value = True

        # Call connection_made
        with patch("logging.Logger.info") as mock_info:
            protocol.connection_made(transport)

            # Verify that the connection was accepted
            transport.close.assert_not_called()
            self.assertEqual(mock_info.call_count, 1)
            self.assertIn("TLS connection established", mock_info.call_args[0][0])

    def test_tls_connection_made_denied_ip(self):
        """Test connection_made with a denied IP."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.protocol.tls import SyslogTLSProtocol

        # Set up the protocol
        protocol = SyslogTLSProtocol(allowed_ips=["192.168.1.1"], deny_action="drop")

        # Mock the transport and SSL object
        ssl_mock = MagicMock()
        ssl_mock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        ssl_mock.version.return_value = "TLSv1.3"
        ssl_mock.getpeercert.return_value = None

        transport = MagicMock()
        transport.get_extra_info.side_effect = lambda key: {
            "peername": ("10.0.0.1", 12345),
            "ssl_object": ssl_mock,
        }.get(key)

        # Set up the IP filter to deny the IP
        self.mock_ip_filter.is_allowed.return_value = False

        # Call connection_made
        with patch("logging.Logger.warning") as mock_warning:
            protocol.connection_made(transport)

            # Verify that the connection was dropped
            transport.close.assert_called_once()
            mock_warning.assert_called_once()
            self.assertIn("Dropped TLS connection", mock_warning.call_args[0][0])


class TestConfigIPFiltering(unittest.TestCase):
    """Test cases for IP filtering configuration."""

    def test_config_defaults(self):
        """Test default IP filtering configuration."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.config import Config

        config = Config()
        self.assertEqual(config.allowed_ips, [])
        self.assertEqual(config.deny_action, "drop")

    def test_config_with_allowed_ips(self):
        """Test IP filtering configuration with allowed IPs."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.config import Config

        config = Config(allowed_ips=["192.168.1.1", "10.0.0.0/24"])
        self.assertEqual(config.allowed_ips, ["192.168.1.1", "10.0.0.0/24"])
        self.assertEqual(config.deny_action, "drop")

    def test_config_with_deny_action(self):
        """Test IP filtering configuration with deny action."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.config import Config

        config = Config(deny_action="reject")
        self.assertEqual(config.allowed_ips, [])
        self.assertEqual(config.deny_action, "reject")

    def test_config_validate_deny_action_valid(self):
        """Test validation of valid deny action."""
        # Local/package imports
        from ziggiz_courier_pickup_syslog.config import Config

        config = Config(deny_action="drop")
        self.assertEqual(config.deny_action, "drop")

        config = Config(deny_action="reject")
        self.assertEqual(config.deny_action, "reject")

    def test_config_validate_deny_action_invalid(self):
        """Test validation of invalid deny action."""
        # Third-party imports
        from pydantic import ValidationError

        # Local/package imports
        from ziggiz_courier_pickup_syslog.config import Config

        with self.assertRaises(ValidationError):
            Config(deny_action="invalid")


if __name__ == "__main__":
    unittest.main()
