# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Real-world framing scenarios tests

# Third-party imports
import pytest

# Local/package imports
# Package imports
from ziggiz_courier_pickup_syslog.protocol.framing import FramingHelper, FramingMode


@pytest.mark.unit
class TestRealWorldFraming:
    """Tests for real-world framing scenarios."""

    def test_transparent_rfc5425_messages(self):
        """Test RFC 5425 compliant framing examples."""
        helper = FramingHelper(framing_mode=FramingMode.TRANSPARENT)

        # Example from RFC 5425
        # Note: This test had an error where the octet count doesn't match the message length
        # "8 TIMESTAMP" - TIMESTAMP is actually 9 bytes long, not 8
        helper.add_data(b"9 TIMESTAMP")
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"TIMESTAMP"

        # Reset the helper to ensure a clean state
        helper.reset()

        # Larger message with content (correcting the octet count to the actual byte count)
        # Using a complete RFC5424 formatted message
        rfc5424_msg = b"<134>1 2003-10-11T22:14:15Z mymachine su 123 ID47 [test@32473 iut=\"3\"] 'su root' failed"
        helper.add_data(f"{len(rfc5424_msg)} ".encode() + rfc5424_msg)
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc5424_msg

        # Maximum allowed length (5 digits)
        helper.add_data(b"12345 " + b"X" * 12345)
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert len(messages[0]) == 12345

        # Invalid formats to test error handling
        with pytest.raises(Exception):
            helper.add_data(b"01 message")  # Leading zero not allowed
            helper.extract_messages()

        with pytest.raises(Exception):
            helper.add_data(b"123456 message")  # Too many digits
            helper.extract_messages()

    def test_non_transparent_common_delimiters(self):
        """Test non-transparent framing with common delimiters."""
        # Test with newline delimiter
        helper = FramingHelper(
            framing_mode=FramingMode.NON_TRANSPARENT, end_of_msg_marker=b"\n"
        )
        helper.add_data(b"message 1\nmessage 2\n")
        messages = helper.extract_messages()
        assert len(messages) == 2
        assert messages[0] == b"message 1"
        assert messages[1] == b"message 2"

        # Test with RFC3164 format message
        helper.reset()
        rfc3164_msg = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
        helper.add_data(rfc3164_msg)
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc3164_msg.rstrip(b"\n")

        # Test with RFC5424 format message
        helper.reset()
        rfc5424_msg = b"<134>1 2003-10-11T22:14:15Z mymachine su 123 ID47 [test@32473 iut=\"3\"] 'su root' failed\n"
        helper.add_data(rfc5424_msg)
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc5424_msg.rstrip(b"\n")

        # Test with RFC3164 format message
        helper.reset()
        rfc3164_msg = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
        helper.add_data(rfc3164_msg)
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc3164_msg.rstrip(b"\n")

        # Test with RFC5424 format message
        helper.reset()
        rfc5424_msg = b"<134>1 2003-10-11T22:14:15Z mymachine su 123 ID47 [test@32473 iut=\"3\"] 'su root' failed\n"
        helper.add_data(rfc5424_msg)
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc5424_msg.rstrip(b"\n")

        # Test with CRLF delimiter
        helper = FramingHelper(
            framing_mode=FramingMode.NON_TRANSPARENT, end_of_msg_marker=b"\r\n"
        )
        helper.add_data(b"message 1\r\nmessage 2\r\n")
        messages = helper.extract_messages()
        assert len(messages) == 2
        assert messages[0] == b"message 1"
        assert messages[1] == b"message 2"

        # Test with null delimiter
        helper = FramingHelper(
            framing_mode=FramingMode.NON_TRANSPARENT, end_of_msg_marker=b"\0"
        )
        helper.add_data(b"message 1\0message 2\0")
        messages = helper.extract_messages()
        assert len(messages) == 2
        assert messages[0] == b"message 1"
        assert messages[1] == b"message 2"

        # Test with custom multi-byte delimiter
        helper = FramingHelper(
            framing_mode=FramingMode.NON_TRANSPARENT, end_of_msg_marker=b"END"
        )
        helper.add_data(b"message 1ENDmessage 2END")
        messages = helper.extract_messages()
        assert len(messages) == 2
        assert messages[0] == b"message 1"
        assert messages[1] == b"message 2"

    def test_auto_mode_mixed_vendor_formats(self):
        """
        Test auto mode with mixed vendor formats.

        Some syslog implementations might send a mix of transparent and
        non-transparent messages within the same connection.
        """
        helper = FramingHelper(framing_mode=FramingMode.AUTO)

        # First send a transparent message
        # Fixing the octet count to match actual message length
        helper.add_data(b"15 transparent msg")
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"transparent msg"

        # Then a non-transparent message with newline
        helper.add_data(b"non-transparent msg\n")
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"non-transparent msg"

        # Reset helper
        helper.reset()

        # Back to transparent
        helper.add_data(b"7 switch!")  # Fixed - remove newline to avoid confusion
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"switch!"

        # Reset again for a clean state
        helper.reset()

        # Send each message separately with correct octet counts
        helper.add_data(b"3 one")
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"one"

        helper.reset()
        helper.add_data(b"non-transparent\n")
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"non-transparent"

        helper.reset()
        helper.add_data(b"10 three four")
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"three four"

    def test_fragmented_messages(self):
        """Test handling of fragmented messages arriving in multiple chunks."""
        helper = FramingHelper(framing_mode=FramingMode.AUTO)

        # Transparent mode fragmentation
        # First part has just the length prefix (correcting octet count to 28)
        helper.add_data(b"28 ")
        messages = helper.extract_messages()
        assert len(messages) == 0  # Not enough data yet

        # Now add the message content in chunks
        helper.add_data(b"This is a ")
        messages = helper.extract_messages()
        assert len(messages) == 0  # Still not enough

        helper.add_data(b"fragmented message")
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"This is a fragmented message"

        # Non-transparent mode fragmentation
        helper.add_data(b"This is another ")
        messages = helper.extract_messages()
        assert len(messages) == 0  # No delimiter yet

        helper.add_data(b"fragmented message\n")
        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == b"This is another fragmented message"

    def test_escape_sequence_parsing(self):
        """Test parsing of various escape sequences for end of message markers."""
        assert FramingHelper.parse_end_of_msg_marker("\\n") == b"\n"
        assert FramingHelper.parse_end_of_msg_marker("\\r\\n") == b"\r\n"
        assert FramingHelper.parse_end_of_msg_marker("\\0") == b"\0"
        assert FramingHelper.parse_end_of_msg_marker("\\x00") == b"\x00"
        assert FramingHelper.parse_end_of_msg_marker("\\x01\\x02") == b"\x01\x02"
        assert FramingHelper.parse_end_of_msg_marker("END") == b"END"
