# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for syslog message formats (RFC3164, RFC5424) in different framing modes

# Third-party imports

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.framing import FramingHelper, FramingMode


class TestSyslogMessageFormats:
    """Tests for syslog message formats with different framing modes."""

    def test_rfc3164_format_transparent(self):
        """Test RFC3164 format messages with transparent framing."""
        helper = FramingHelper(framing_mode=FramingMode.TRANSPARENT)

        # RFC3164 format message
        rfc3164_msg = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        helper.add_data(f"{len(rfc3164_msg)} ".encode() + rfc3164_msg)

        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc3164_msg

    def test_rfc3164_format_non_transparent(self):
        """Test RFC3164 format messages with non-transparent framing."""
        helper = FramingHelper(
            framing_mode=FramingMode.NON_TRANSPARENT, end_of_msg_marker=b"\n"
        )

        # RFC3164 format message with delimiter
        rfc3164_msg = b"<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8\n"
        helper.add_data(rfc3164_msg)

        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc3164_msg.rstrip(b"\n")

    def test_rfc5424_format_transparent(self):
        """Test RFC5424 format messages with transparent framing."""
        helper = FramingHelper(framing_mode=FramingMode.TRANSPARENT)

        # Complete RFC5424 format message
        rfc5424_msg = b'<134>1 2003-10-11T22:14:15Z mymachine su 123 ID47 [origin software="test" swVersion="1.0"] \'su root\' failed'
        helper.add_data(f"{len(rfc5424_msg)} ".encode() + rfc5424_msg)

        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc5424_msg

    def test_rfc5424_format_non_transparent(self):
        """Test RFC5424 format messages with non-transparent framing."""
        helper = FramingHelper(
            framing_mode=FramingMode.NON_TRANSPARENT, end_of_msg_marker=b"\n"
        )

        # Complete RFC5424 format message with delimiter
        rfc5424_msg = b'<134>1 2003-10-11T22:14:15Z mymachine su 123 ID47 [origin software="test" swVersion="1.0"] \'su root\' failed\n'
        helper.add_data(rfc5424_msg)

        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc5424_msg.rstrip(b"\n")

    def test_rfc5424_structured_data(self):
        """Test RFC5424 format with different structured data formats."""
        helper = FramingHelper(framing_mode=FramingMode.TRANSPARENT)

        # Message with multiple structured data elements
        rfc5424_multi_sd = b'<165>1 2003-10-11T22:14:15Z mymachine su 123 ID47 [exampleSDID@32473 iut="3" eventSource="App" eventID="1011"][examplePriority@32473 class="high"] Application event'
        helper.add_data(f"{len(rfc5424_multi_sd)} ".encode() + rfc5424_multi_sd)

        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc5424_multi_sd

        # Message with no structured data
        helper.reset()
        rfc5424_no_sd = (
            b"<165>1 2003-10-11T22:14:15Z mymachine su 123 ID47 - Application event log"
        )
        helper.add_data(f"{len(rfc5424_no_sd)} ".encode() + rfc5424_no_sd)

        messages = helper.extract_messages()
        assert len(messages) == 1
        assert messages[0] == rfc5424_no_sd
