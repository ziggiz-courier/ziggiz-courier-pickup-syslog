# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Common module for framing-related imports to ensure consistent version is used

# Standard library imports
from enum import Enum


class FramingMode(Enum):
    """
    Enumeration for the syslog message framing mode.

    Values:
        AUTO: Automatically detect framing mode (tries transparent, then non-transparent).
        TRANSPARENT: Octet-counting framing (RFC 5425, each message prefixed with length).
        NON_TRANSPARENT: Delimiter-based framing (e.g., newline or custom marker).
    """

    AUTO = "auto"
    TRANSPARENT = "transparent"
    NON_TRANSPARENT = "non_transparent"


class FramingDetectionError(Exception):
    """
    Exception raised when there's an error in framing detection.
    """
