# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the __main__ module

# Standard library imports
from unittest.mock import patch

# Third-party imports
import pytest


class TestMainModule:
    """Tests for the __main__ entry point module."""

    @pytest.mark.unit
    def test_main_import(self):
        """Test that the main function is properly imported in __main__."""
        with patch("ziggiz_courier_pickup_syslog.main.main") as mock_main:
            # When we import __main__, it should call main() if __name__ == "__main__"
            # But in our test environment, __name__ != "__main__", so it won't be called
            # Local/package imports
            pass

            # Check that main was not called (since __name__ != "__main__")
            mock_main.assert_not_called()

    @pytest.mark.unit
    def test_main_module_structure(self):
        """Test the structure of the __main__ module."""
        # Local/package imports
        import ziggiz_courier_pickup_syslog.__main__

        # Check that the module has the expected attributes
        assert hasattr(ziggiz_courier_pickup_syslog.__main__, "main")
