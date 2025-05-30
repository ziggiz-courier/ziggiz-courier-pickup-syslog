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

from unittest.mock import MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.framing import (
    FramingDetectionError,
    FramingMode,
)
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
    # Check that framing_helper is initialized
    assert hasattr(protocol, "framing_helper")
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
    # Check log message includes peer credentials
    assert "Unix Stream connection established" in caplog.text


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
    # Check log message includes peername
    assert "Unix Stream connection established" in caplog.text


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

    # Check the transport is set and log message is created
    assert protocol.transport == mock_transport
    assert protocol.peername is None
    assert "Unix Stream connection established" in caplog.text


@pytest.mark.integration
@pytest.mark.asyncio
async def test_connection_made(unix_protocol):
    """Test that connection_made logs properly."""
    transport = MagicMock()
    transport.get_extra_info.return_value = "test-peer"

    unix_protocol.connection_made(transport)

    assert unix_protocol.transport == transport
    assert unix_protocol.peername == "test-peer"
    unix_protocol.logger.debug.assert_called_once()


@pytest.mark.integration
@pytest.mark.asyncio
async def test_get_buffer(unix_protocol):
    """Test that get_buffer returns a buffer of correct size."""
    buffer = unix_protocol.get_buffer(1024)

    assert isinstance(buffer, bytearray)
    assert len(buffer) == 1024

    # Test with size larger than max
    big_buffer = unix_protocol.get_buffer(100000)
    assert len(big_buffer) == unix_protocol.max_buffer_size


@pytest.mark.integration
@pytest.mark.asyncio
async def test_buffer_updated(unix_protocol):
    """Test that buffer_updated processes data correctly."""
    # Setup
    test_data = b"test message 1\ntest message 2\n"
    unix_protocol._read_buffer = bytearray(test_data)
    unix_protocol.peername = "test-peer"

    # Enable debug logging for syslog message processing (for test compatibility)
    unix_protocol._test_force_log = True

    # Enable debug logging for syslog message processing (for test compatibility)
    unix_protocol._test_force_log = True
    # Call buffer_updated with the length of our test data
    unix_protocol.buffer_updated(len(test_data))

    # Check that messages were processed (now at debug level)
    assert unix_protocol.logger.debug.call_count >= 2
    assert unix_protocol.buffer == bytearray()


@pytest.mark.unit
def test_buffer_updated_with_decoder(caplog):
    """Test buffer_updated method with decoder."""

    protocol = SyslogUnixProtocol()
    protocol.peername = "/var/run/syslog.sock"
    protocol.logger = MagicMock()
    # Enable test mode for logging (only event_type and peer in log extra)
    protocol._test_force_log = True

    # Patch the decoder's decode method
    with patch.object(protocol.decoder, "decode") as mock_decode:
        # Setup mock decoder response
        mock_decoded = MagicMock()
        mock_decoded.__class__.__name__ = "EventEnvelopeBaseModel"
        mock_decode.return_value = mock_decoded

        # Create test data with a complete message
        test_data = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
        protocol._read_buffer = bytearray(test_data)

        # Call buffer_updated
        protocol.buffer_updated(len(test_data))

        # Check that the decoder was called
        mock_decode.assert_called_once()
        # Check that the message was logged at info level with correct extra fields
        protocol.logger.info.assert_any_call(
            "Syslog message received",
            extra={
                "peer": "/var/run/syslog.sock",
                "event_type": "EventEnvelopeBaseModel",
                "log_msg": "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
            },
        )


@pytest.mark.unit
def test_buffer_updated_transparent_framing(caplog):
    """Test buffer_updated with transparent framing."""
    caplog.set_level(logging.DEBUG)
    protocol = SyslogUnixProtocol(framing_mode="transparent")
    protocol.peername = "/var/run/syslog.sock"

    # Create test data with a transparent framing message (length + message)
    # Format: <length><space><message>
    test_data = b"47 <34>Oct 11 22:14:15 mymachine su: 'su root' failed"
    protocol._read_buffer = bytearray(test_data)

    # Call buffer_updated
    protocol.buffer_updated(len(test_data))

    # Check debug log for buffer size
    assert "Buffer size after adding data" in caplog.text


@pytest.mark.unit
def test_buffer_updated_framing_error(caplog):
    """Test buffer_updated method with framing error."""
    caplog.set_level(logging.ERROR)
    protocol = SyslogUnixProtocol(framing_mode="transparent")
    protocol.peername = "/var/run/syslog.sock"
    protocol.transport = MagicMock()

    # Create a method that raises FramingDetectionError when called
    def mock_add_data(data):
        raise FramingDetectionError("Test framing error")

    protocol.framing_helper.add_data = mock_add_data

    # Call buffer_updated with test data
    test_data = b"invalid data"
    protocol._read_buffer = bytearray(test_data)
    protocol.buffer_updated(len(test_data))

    # Check that the error was logged
    assert "Framing error" in caplog.text

    # Note: The "Closing connection due to framing error" message is logged at WARNING level
    # but we set the caplog level to ERROR, so we won't see it.
    # Instead, we'll just check that transport.close was called
    protocol.transport.close.assert_called_once()


@pytest.mark.integration
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


@pytest.mark.unit
def test_eof_received_with_partial_transparent_message(caplog):
    """Test eof_received with partial transparent message."""
    caplog.set_level(logging.WARNING)
    protocol = SyslogUnixProtocol(framing_mode="transparent")
    protocol.peername = "/var/run/syslog.sock"

    # Create a partial transparent message (length prefix but incomplete message)
    protocol.framing_helper._buffer.extend(b"100 <34>Oct 11 22:14:15 mymachine")

    # Call eof_received
    result = protocol.eof_received()

    # Check that warning about incomplete message was logged
    assert "Incomplete transparent message from /var/run/syslog.sock" in caplog.text
    assert "received" in caplog.text
    assert "of 100 bytes" in caplog.text
    # Check return value (should be False to close the transport)
    assert result is False


@pytest.mark.unit
def test_eof_received_with_non_transparent_data_in_transparent_mode(caplog):
    """Test eof_received with non-transparent data in transparent mode."""
    # Set log level to capture ERROR messages
    caplog.set_level(logging.ERROR)
    protocol = SyslogUnixProtocol(framing_mode="transparent")
    protocol.peername = "/var/run/syslog.sock"

    # Add non-transparent data to the buffer
    protocol.framing_helper._buffer.extend(b"<34>Oct 11 22:14:15 mymachine su: message")

    # Call eof_received
    result = protocol.eof_received()

    # In the actual implementation, this causes an error because the data doesn't match
    # the transparent framing format (should start with a number)
    assert "Error processing final data from /var/run/syslog.sock" in caplog.text
    assert "Invalid transparent framing format" in caplog.text

    # Check return value (should be False to close the transport)
    assert result is False


@pytest.mark.integration
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

    assert unix_protocol.logger.debug.called
    assert unix_protocol.buffer == bytearray()
    assert unix_protocol._read_buffer is None
    assert unix_protocol.transport is None


@pytest.mark.unit
def test_buffer_property_setter():
    """Test the buffer property setter."""
    protocol = SyslogUnixProtocol()

    # Set a value to the buffer
    test_data = b"test data"
    protocol.buffer = test_data

    # Check that the buffer contains the data
    assert protocol.buffer == bytearray(test_data)

    # Set a new value
    new_data = b"new data"
    protocol.buffer = new_data

    # Check that the buffer was cleared and contains the new data
    assert protocol.buffer == bytearray(new_data)


@pytest.mark.unit
def test_unix_with_different_framing_modes():
    """Test Unix protocol with different framing modes."""
    # Test with non_transparent mode
    protocol_non_transparent = SyslogUnixProtocol(framing_mode="non_transparent")
    assert (
        protocol_non_transparent.framing_helper.framing_mode
        == FramingMode.NON_TRANSPARENT
    )

    # Test with transparent mode
    protocol_transparent = SyslogUnixProtocol(framing_mode="transparent")
    assert protocol_transparent.framing_helper.framing_mode == FramingMode.TRANSPARENT

    # Test with auto mode (default)
    protocol_auto = SyslogUnixProtocol()
    assert protocol_auto.framing_helper.framing_mode == FramingMode.AUTO
