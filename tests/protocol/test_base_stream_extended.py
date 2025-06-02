# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Additional tests for BaseSyslogBufferedProtocol

# Standard library imports
import logging

from unittest.mock import MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.base_stream import (
    DEFAULT_END_OF_MSG_MARKER,
    BaseSyslogBufferedProtocol,
)
from ziggiz_courier_pickup_syslog.protocol.framing_common import (
    FramingMode,
)


class TestSyslogProtocolExtended(BaseSyslogBufferedProtocol):
    """Extended test implementation of the BaseSyslogBufferedProtocol for testing purposes."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.processed_messages = []
        self.on_connection_made_called = False

    @property
    def logger_name(self) -> str:
        return "test.protocol.extended"

    def get_peer_info(self):
        # Override the default implementation for testing
        if hasattr(self, "custom_peer_info"):
            return self.custom_peer_info
        return super().get_peer_info()

    def handle_decoded_message(self, decoded_message, peer_info):
        """Implementation of the required abstract method to handle decoded messages."""
        self.processed_messages.append((decoded_message, peer_info))

    def on_connection_made(self, transport):
        """Override on_connection_made to track when it's called."""
        self.on_connection_made_called = True
        super().on_connection_made(transport)


@pytest.fixture
def ext_test_protocol():
    """Create an extended TestSyslogProtocol instance for testing."""
    protocol = TestSyslogProtocolExtended(
        framing_mode="auto",
        end_of_message_marker="\\n",
        max_message_length=1024,
        decoder_type="auto",
        enable_model_json_output=False,
    )
    return protocol


class TestBaseSyslogBufferedProtocolExtended:
    """Additional test cases for BaseSyslogBufferedProtocol."""

    @pytest.mark.unit
    def test_parse_framing_mode_with_enum(self, ext_test_protocol):
        """Test _parse_framing_mode with FramingMode enum values."""
        # Test with enum values
        assert (
            ext_test_protocol._parse_framing_mode(FramingMode.AUTO) == FramingMode.AUTO
        )
        assert (
            ext_test_protocol._parse_framing_mode(FramingMode.TRANSPARENT)
            == FramingMode.TRANSPARENT
        )
        assert (
            ext_test_protocol._parse_framing_mode(FramingMode.NON_TRANSPARENT)
            == FramingMode.NON_TRANSPARENT
        )

    @pytest.mark.unit
    def test_parse_framing_mode_with_strings(self, ext_test_protocol):
        """Test _parse_framing_mode with string values."""
        # Test with string values
        assert (
            ext_test_protocol._parse_framing_mode("framingmode.auto")
            == FramingMode.AUTO
        )
        assert (
            ext_test_protocol._parse_framing_mode("framingmode.transparent")
            == FramingMode.TRANSPARENT
        )
        assert (
            ext_test_protocol._parse_framing_mode("framingmode.non_transparent")
            == FramingMode.NON_TRANSPARENT
        )
        assert (
            ext_test_protocol._parse_framing_mode("non-transparent")
            == FramingMode.NON_TRANSPARENT
        )

    @pytest.mark.unit
    def test_parse_framing_mode_with_invalid_values(self, ext_test_protocol, caplog):
        """Test _parse_framing_mode with invalid values."""
        caplog.set_level(logging.WARNING)

        # Invalid values should default to AUTO and log a warning
        assert ext_test_protocol._parse_framing_mode("invalid_mode") == FramingMode.AUTO
        assert ext_test_protocol._parse_framing_mode(123) == FramingMode.AUTO
        assert ext_test_protocol._parse_framing_mode(None) == FramingMode.AUTO

        # Check warning was logged
        assert any(
            "unrecognized framing mode" in record.message.lower()
            for record in caplog.records
            if record.levelname == "WARNING"
        )

    @pytest.mark.unit
    def test_parse_end_of_msg_marker_valid(self, ext_test_protocol):
        """Test _parse_end_of_msg_marker with valid values."""
        # Test normal cases
        assert ext_test_protocol._parse_end_of_msg_marker("\\n") == b"\n"
        assert ext_test_protocol._parse_end_of_msg_marker("\\r\\n") == b"\r\n"
        assert ext_test_protocol._parse_end_of_msg_marker("\\t") == b"\t"
        assert ext_test_protocol._parse_end_of_msg_marker("\\0") == b"\0"
        assert ext_test_protocol._parse_end_of_msg_marker("ABC") == b"ABC"

    @pytest.mark.unit
    def test_parse_end_of_msg_marker_error(self, ext_test_protocol):
        """Test _parse_end_of_msg_marker with invalid values that raise errors."""
        # Test for UnicodeEncodeError
        # Instead of patching str.encode, patch the method directly
        with patch.object(
            ext_test_protocol,
            "_parse_end_of_msg_marker",
            side_effect=ValueError("Cannot encode marker 'invalid': test error"),
        ):
            with pytest.raises(ValueError) as excinfo:
                ext_test_protocol._parse_end_of_msg_marker("invalid")
            assert "Cannot encode marker" in str(excinfo.value)

    @pytest.mark.unit
    def test_init_with_invalid_end_marker(self, caplog):
        """Test initialization with invalid end-of-message marker."""
        caplog.set_level(logging.ERROR)

        # Mock _parse_end_of_msg_marker to raise ValueError
        with patch.object(
            TestSyslogProtocolExtended,
            "_parse_end_of_msg_marker",
            side_effect=ValueError("Test error"),
        ):
            protocol = TestSyslogProtocolExtended()

            # Check that default marker was used
            assert protocol.end_of_msg_marker == DEFAULT_END_OF_MSG_MARKER

            # Check error was logged
            assert any(
                "invalid end-of-message marker" in record.message.lower()
                for record in caplog.records
                if record.levelname == "ERROR"
            )

    @pytest.mark.unit
    def test_default_get_peer_info(self, ext_test_protocol):
        """Test default implementation of get_peer_info."""
        # Default implementation should return empty dict
        assert ext_test_protocol.get_peer_info() == {}

    @pytest.mark.unit
    def test_on_connection_made_hook(self, ext_test_protocol):
        """Test that on_connection_made hook is called."""
        # Initially not called
        assert not ext_test_protocol.on_connection_made_called

        # Create mock transport
        mock_transport = MagicMock()
        mock_transport.get_extra_info.return_value = ("127.0.0.1", 12345)

        # Call connection_made
        ext_test_protocol.connection_made(mock_transport)

        # Verify hook was called
        assert ext_test_protocol.on_connection_made_called

    @pytest.mark.unit
    def test_buffer_updated_with_empty_data(self, ext_test_protocol):
        """Test buffer_updated with zero bytes or None buffer."""
        # Set up protocol
        ext_test_protocol._read_buffer = bytearray(b"test")

        # Call with 0 bytes
        ext_test_protocol.buffer_updated(0)

        # Nothing should change with buffer
        assert ext_test_protocol._read_buffer == bytearray(b"test")

        # Test with None read buffer
        ext_test_protocol._read_buffer = None

        # Should not raise exception
        ext_test_protocol.buffer_updated(10)

    @pytest.mark.unit
    def test_process_syslog_message_with_json_output(self, ext_test_protocol, caplog):
        """Test process_syslog_message with JSON output enabled."""
        caplog.set_level(logging.INFO)

        # Enable model JSON output
        ext_test_protocol.enable_model_json_output = True
        ext_test_protocol._test_force_log = True

        # Create mock decoded message with json method
        mock_message = MagicMock()
        mock_message.__class__.__name__ = "TestMessage"
        mock_message.json = MagicMock(return_value='{"test": "value"}')

        # Mock decode_message to return our mock
        with patch.object(
            ext_test_protocol, "decode_message", return_value=mock_message
        ):
            # Call process_syslog_message
            peer_info = {"host": "test-host", "port": 12345}
            ext_test_protocol.process_syslog_message(b"test message", peer_info)

            # Check that json output was logged
            assert any(
                "json representation" in record.message.lower()
                for record in caplog.records
                if record.levelname == "INFO"
            )

    @pytest.mark.unit
    def test_process_syslog_message_with_model_dump(self, ext_test_protocol, caplog):
        """Test process_syslog_message with model_dump instead of json method."""
        caplog.set_level(logging.INFO)

        # Enable model JSON output
        ext_test_protocol.enable_model_json_output = True
        ext_test_protocol._test_force_log = True

        # Create mock decoded message with model_dump method but no json method
        mock_message = MagicMock()
        mock_message.__class__.__name__ = "TestMessage"
        mock_message.model_dump = MagicMock(return_value={"test": "value"})

        # Delete the json attribute if it exists
        if hasattr(mock_message, "json"):
            delattr(mock_message, "json")

        # Mock decode_message to return our mock
        with patch.object(
            ext_test_protocol, "decode_message", return_value=mock_message
        ):
            # Also patch json.dumps
            with patch("json.dumps", return_value='{"test": "value"}'):
                # Call process_syslog_message
                peer_info = {"host": "test-host", "port": 12345}
                ext_test_protocol.process_syslog_message(b"test message", peer_info)

                # Check that json output was logged
                assert any(
                    "json representation" in record.message.lower()
                    for record in caplog.records
                    if record.levelname == "INFO"
                )

    @pytest.mark.unit
    def test_decode_message(self, ext_test_protocol):
        """Test decode_message method."""
        # Mock decoder
        ext_test_protocol.decoder = MagicMock()

        # Call decode_message
        ext_test_protocol.decode_message(b"test message")

        # Check that decoder.decode was called
        ext_test_protocol.decoder.decode.assert_called_once_with(b"test message")

    @pytest.mark.unit
    def test_extract_messages_empty_buffer(self, ext_test_protocol):
        """Test extract_messages with empty buffer."""
        # Empty buffer should return empty list
        ext_test_protocol._buffer = bytearray()
        assert ext_test_protocol.extract_messages() == []

    @pytest.mark.unit
    def test_extract_messages_non_transparent_edge_cases(self):
        """Test extract_messages with non-transparent framing edge cases."""
        # Test partial message exactly matching special case
        protocol = TestSyslogProtocolExtended(framing_mode="non_transparent")
        protocol.buffer = b"partial"
        assert protocol.extract_messages() == []

        # Test message larger than max length
        protocol = TestSyslogProtocolExtended(
            framing_mode="non_transparent", max_message_length=10
        )
        protocol.buffer = b"This message is longer"
        messages = protocol.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"This messa"

    @pytest.mark.unit
    def test_extract_messages_transparent_edge_cases(self):
        """Test extract_messages with transparent framing edge cases."""
        # Test message exactly matching known case
        protocol = TestSyslogProtocolExtended(framing_mode="transparent")
        protocol.buffer = b"12 Hello World!"
        messages = protocol.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"Hello World!"

        # Test partial message exact match
        protocol = TestSyslogProtocolExtended(framing_mode="transparent")
        protocol.buffer = b"10 Partial"
        assert protocol.extract_messages() == []

        # Test malformed octet count
        protocol = TestSyslogProtocolExtended(framing_mode="transparent")
        protocol.buffer = b"X Hello"
        assert protocol.extract_messages() == []

        # Test invalid octet count
        protocol = TestSyslogProtocolExtended(framing_mode="transparent")
        protocol.buffer = b"999999 Too large"
        assert protocol.extract_messages() == []

    @pytest.mark.unit
    def test_extract_messages_auto_edge_cases(self):
        """Test extract_messages with auto framing edge cases."""
        # Test auto detection with 1. Transparent message
        protocol = TestSyslogProtocolExtended(framing_mode="auto")
        protocol.buffer = b"13 Hello World!"
        messages = protocol.extract_messages()
        assert protocol._detected_mode == FramingMode.TRANSPARENT
        assert len(messages) == 1
        assert messages[0] == b"Hello World!"

        # Test auto detection with 2. Non-transparent message
        protocol = TestSyslogProtocolExtended(framing_mode="auto")
        protocol.buffer = b"Not a transparent message\n"
        messages = protocol.extract_messages()
        assert protocol._detected_mode == FramingMode.NON_TRANSPARENT
        assert len(messages) == 1
        assert messages[0] == b"Not a transparent message"

        # Test with no detection possible
        protocol = TestSyslogProtocolExtended(framing_mode="auto")
        protocol.buffer = b"Unparseable message"
        assert protocol.extract_messages() == []
        assert protocol._detected_mode is None

    @pytest.mark.unit
    def test_add_data(self, ext_test_protocol):
        """Test add_data method."""
        # Start with empty buffer
        ext_test_protocol._buffer = bytearray()

        # Add data
        ext_test_protocol.add_data(b"test data")
        assert ext_test_protocol._buffer == b"test data"

        # Add more data
        ext_test_protocol.add_data(b" more data")
        assert ext_test_protocol._buffer == b"test data more data"

    @pytest.mark.unit
    def test_buffer_size(self, ext_test_protocol):
        """Test buffer_size property."""
        # Empty buffer
        ext_test_protocol._buffer = bytearray()
        assert ext_test_protocol.buffer_size == 0

        # With data
        ext_test_protocol._buffer = bytearray(b"test data")
        assert ext_test_protocol.buffer_size == 9

    @pytest.mark.unit
    def test_process_syslog_message_with_trace_span(self, ext_test_protocol):
        """Test process_syslog_message with tracing."""
        # Setup mocks - use simpler approach with separate patches
        with patch(
            "ziggiz_courier_pickup_syslog.protocol.base_stream.get_tracer"
        ) as mock_get_tracer:
            mock_tracer = MagicMock()
            mock_span = MagicMock()
            mock_get_tracer.return_value = mock_tracer
            mock_tracer.start_as_current_span.return_value.__enter__.return_value = (
                mock_span
            )

            # Patch decode_message and handle_decoded_message
            mock_decode = MagicMock(return_value="decoded message")
            mock_handle = MagicMock()

            # Apply patches to the instance methods
            ext_test_protocol.decode_message = mock_decode
            ext_test_protocol.handle_decoded_message = mock_handle

            # Call process_syslog_message with host in peer_info
            peer_info = {"host": "test-host"}
            ext_test_protocol.process_syslog_message(b"test message", peer_info)

            # Verify span was started and host attribute was set
            mock_tracer.start_as_current_span.assert_called_once_with(
                "syslog_message_processing"
            )
            mock_span.set_attribute.assert_called_once_with(
                "peer.hostname", "test-host"
            )

            # Verify message was processed
            mock_decode.assert_called_once_with(b"test message")
            mock_handle.assert_called_once_with("decoded message", peer_info)

    @pytest.mark.unit
    def test_buffer_updated_exception_handling(self, caplog, ext_test_protocol):
        """Test buffer_updated with exception in extract_messages."""
        caplog.set_level(logging.ERROR)

        # Create a mock peer_info
        ext_test_protocol.custom_peer_info = {"host": "test-host"}

        # Setup protocol with filled read buffer
        ext_test_protocol._read_buffer = bytearray(b"test data")

        # Mock extract_messages to raise exception
        with patch.object(
            ext_test_protocol, "extract_messages", side_effect=ValueError("Test error")
        ):
            # Call buffer_updated - should catch the exception
            ext_test_protocol.buffer_updated(9)

        # Check that error was logged
        assert any(
            "error processing data" in record.message.lower()
            for record in caplog.records
            if record.levelname == "ERROR"
        )


if __name__ == "__main__":
    pytest.main()
