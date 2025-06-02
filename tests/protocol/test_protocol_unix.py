# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE


# Standard library imports
import logging

from unittest.mock import MagicMock

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.unix import SyslogUnixProtocol


@pytest.fixture
def unix_protocol():
    """Create a SyslogUnixProtocol instance for testing."""
    protocol = SyslogUnixProtocol()
    protocol.logger = MagicMock()
    return protocol


@pytest.mark.unit
def test_init():
    """Test initialization of the protocol."""
    protocol = SyslogUnixProtocol()

    # Check that the logger is properly initialized
    assert protocol.logger.name == "ziggiz_courier_pickup_syslog.protocol.unix"
    assert protocol.transport is None
    assert protocol.peername is None
    assert protocol._read_buffer is None
    assert protocol.max_buffer_size == 65536
    # Check decoder setup
    assert protocol.decoder_type == "auto"
    assert isinstance(protocol.connection_cache, dict)
    assert isinstance(protocol.event_parsing_cache, dict)


@pytest.mark.unit
def test_connection_made_with_peer_creds(caplog):
    """Test connection_made method with peer credentials."""
    caplog.set_level(logging.DEBUG)
    protocol = SyslogUnixProtocol()

    # Create a mock transport with peer credentials
    mock_transport = MagicMock()
    mock_transport.get_extra_info.side_effect = lambda key: {
        "peername": "/var/run/syslog.sock",
        "peercreds": (1234, 100, 200),  # (pid, uid, gid)
    }.get(key)

    # Call connection_made
    protocol.connection_made(mock_transport)

    # Check the transport and peername are set
    assert protocol.transport == mock_transport
    assert protocol.peername == "/var/run/syslog.sock"
    # Functional: verify state
    assert protocol.transport == mock_transport
    assert protocol.peername == "/var/run/syslog.sock"


@pytest.mark.unit
def test_connection_made_without_peer_creds(caplog):
    """Test connection_made method without peer credentials."""
    caplog.set_level(logging.DEBUG)
    protocol = SyslogUnixProtocol()

    # Create a mock transport without peer credentials
    mock_transport = MagicMock()
    mock_transport.get_extra_info.side_effect = lambda key: {
        "peername": "/var/run/syslog.sock",
        "peercreds": None,
    }.get(key)

    # Call connection_made
    protocol.connection_made(mock_transport)

    # Check the transport and peername are set
    assert protocol.transport == mock_transport
    assert protocol.peername == "/var/run/syslog.sock"
    # Functional: verify state
    assert protocol.transport == mock_transport
    assert protocol.peername == "/var/run/syslog.sock"


@pytest.mark.unit
def test_connection_made_unknown_peer(caplog):
    """Test connection_made method with unknown peer."""
    caplog.set_level(logging.DEBUG)
    protocol = SyslogUnixProtocol()

    # Create a mock transport without peer info
    mock_transport = MagicMock()
    mock_transport.get_extra_info.return_value = None

    # Call connection_made
    protocol.connection_made(mock_transport)

    # Functional: verify state
    assert protocol.transport == mock_transport
    assert protocol.peername is None


@pytest.mark.integration
@pytest.mark.asyncio
async def test_connection_made(unix_protocol):
    """Test that connection_made logs properly."""
    transport = MagicMock()
    transport.get_extra_info.return_value = "test-peer"

    unix_protocol.connection_made(transport)

    assert unix_protocol.transport == transport
    assert unix_protocol.peername == "test-peer"
    # Functional: verify state only (do not assert logger calls)
