#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
"""
Test script to validate handling of partial messages in transparent framing mode.

This script specifically tests the EOF handling for partial transparent-framed messages.
"""

# Standard library imports
import asyncio
import logging

from unittest.mock import MagicMock

# Third-party imports
import pytest

# Local/package imports
from ziggiz_courier_pickup_syslog.protocol.unix import SyslogUnixProtocol

# Configure logging
logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")
logger = logging.getLogger("test_partial_transparent")


class MockTransport(MagicMock):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.closed = False

    def close(self):
        self.closed = True


@pytest.mark.integration
@pytest.mark.integration
@pytest.mark.asyncio
async def test_partial_transparent_message_eof():
    """Test EOF handling with partial transparent messages."""
    print("\n=== Testing EOF with Partial Transparent Messages ===")

    # Create a protocol instance with transparent framing mode
    protocol = SyslogUnixProtocol(framing_mode="transparent")
    protocol.logger = logger

    # Create a mock transport
    transport = MockTransport()
    transport.get_extra_info.return_value = "test-peer"

    # Connect the protocol
    protocol.connection_made(transport)

    # Test cases: Different partial message scenarios
    test_cases = [
        # Case 1: Only octet count is received
        b"100 ",  # Expect warning about partial message
        # Case 2: Partial octet count (split in the middle of the count)
        b"10",  # Expect warning about unparsed data
        # Case 3: Complete octet count but partial message
        b"10 Hello",  # Expect warning about incomplete message
        # Case 4: Garbage data (not valid transparent framing)
        b"garbage",  # Expect warning about unparsed data
    ]

    for i, test_data in enumerate(test_cases):
        print(f"\nTest case {i + 1}: {test_data}")

        # Reset the protocol state
        protocol.framing_helper.reset()
        transport.closed = False
        logger.debug(f"Testing with data: {test_data}")

        # Add the test data to the buffer
        protocol.buffer_updated = MagicMock()
        protocol.framing_helper.add_data(test_data)

        # Call eof_received
        result = protocol.eof_received()

        # Check result
        print(f"Transport would be closed: {not result}")
        print(f"Buffer cleared: {len(protocol.framing_helper._buffer) == 0}")


if __name__ == "__main__":
    asyncio.run(test_partial_transparent_message_eof())
