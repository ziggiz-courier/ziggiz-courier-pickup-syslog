# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for Unix Stream protocol

# Standard library imports

# Standard library imports
from unittest.mock import MagicMock

# Third-party imports
import pytest

# Local/package imports
# Package/Application imports
from ziggiz_courier_pickup_syslog.protocol.unix import SyslogUnixProtocol


@pytest.fixture
def unix_protocol():
    """Create a SyslogUnixProtocol instance for testing."""
    protocol = SyslogUnixProtocol()
    protocol.logger = MagicMock()
    return protocol


@pytest.mark.asyncio
async def test_connection_made(unix_protocol):
    """Test that connection_made logs properly."""
    transport = MagicMock()
    transport.get_extra_info.return_value = "test-peer"

    unix_protocol.connection_made(transport)

    assert unix_protocol.transport == transport
    assert unix_protocol.peername == "test-peer"
    unix_protocol.logger.info.assert_called_once()


@pytest.mark.asyncio
async def test_get_buffer(unix_protocol):
    """Test that get_buffer returns a buffer of correct size."""
    buffer = unix_protocol.get_buffer(1024)

    assert isinstance(buffer, bytearray)
    assert len(buffer) == 1024

    # Test with size larger than max
    big_buffer = unix_protocol.get_buffer(100000)
    assert len(big_buffer) == unix_protocol.max_buffer_size


@pytest.mark.asyncio
async def test_buffer_updated(unix_protocol):
    """Test that buffer_updated processes data correctly."""
    # Setup
    test_data = b"test message 1\ntest message 2\n"
    unix_protocol._read_buffer = bytearray(test_data)
    unix_protocol.peername = "test-peer"

    # Call buffer_updated with the length of our test data
    unix_protocol.buffer_updated(len(test_data))

    # Check that messages were processed
    assert unix_protocol.logger.info.call_count == 2
    assert unix_protocol.buffer == bytearray()


@pytest.mark.asyncio
async def test_eof_received(unix_protocol):
    """Test that eof_received processes any remaining data."""
    # Setup with data in the buffer
    unix_protocol.buffer = bytearray(b"final message")
    unix_protocol.peername = "test-peer"

    # Call eof_received
    result = unix_protocol.eof_received()

    # Check that the final message was processed
    assert unix_protocol.logger.info.called
    assert unix_protocol.buffer == bytearray()
    assert result is False  # Should return False to close the transport


@pytest.mark.asyncio
async def test_connection_lost(unix_protocol):
    """Test that connection_lost cleans up resources."""
    # Setup
    unix_protocol._read_buffer = bytearray(b"some data")
    unix_protocol.buffer = bytearray(b"buffer data")
    unix_protocol.transport = MagicMock()
    unix_protocol.peername = "test-peer"

    # Test with exception
    exception = Exception("Test error")
    unix_protocol.connection_lost(exception)

    assert unix_protocol.logger.warning.called
    assert unix_protocol.buffer == bytearray()
    assert unix_protocol._read_buffer is None
    assert unix_protocol.transport is None

    # Reset for test without exception
    unix_protocol.logger.reset_mock()
    unix_protocol.buffer = bytearray(b"buffer data")
    unix_protocol._read_buffer = bytearray(b"some data")
    unix_protocol.transport = MagicMock()

    # Test without exception
    unix_protocol.connection_lost(None)

    assert unix_protocol.logger.info.called
    assert unix_protocol.buffer == bytearray()
    assert unix_protocol._read_buffer is None
    assert unix_protocol.transport is None
