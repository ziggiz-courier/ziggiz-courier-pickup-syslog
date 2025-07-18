# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# Tests for the decoder factory module

# Standard library imports


# Standard library imports
from unittest.mock import MagicMock, patch

# Third-party imports
import pytest

# Local/package imports
# Local imports
from ziggiz_courier_pickup_syslog.protocol.decoder_factory import DecoderFactory


@pytest.mark.unit
class TestDecoderFactory:
    """Tests for the DecoderFactory class."""

    def test_placeholder(self):
        """Placeholder test for decoder factory - to be implemented."""

    def test_create_decoder(self):
        """Test create_decoder method with auto decoder type."""
        decoder = DecoderFactory.create_decoder("auto")
        assert decoder.__class__.__name__ == "UnknownSyslogDecoder"

    def test_create_decoder_with_custom_cache(self):
        """Test create_decoder method with custom caches."""
        conn_cache = {"test": "connection"}
        event_cache = {"test": "event"}
        decoder = DecoderFactory.create_decoder(
            "rfc5424", connection_cache=conn_cache, event_parsing_cache=event_cache
        )
        assert decoder.__class__.__name__ == "SyslogRFC5424Decoder"

    @pytest.mark.parametrize(
        "decoder_type,expected_class",
        [
            ("auto", "UnknownSyslogDecoder"),
            ("rfc3164", "SyslogRFC3164Decoder"),
            ("rfc5424", "SyslogRFC5424Decoder"),
            ("base", "SyslogRFCBaseDecoder"),
        ],
    )
    def test_create_decoder_types(self, decoder_type, expected_class):
        """Test create_decoder with various decoder types."""
        decoder = DecoderFactory.create_decoder(decoder_type)
        assert decoder.__class__.__name__ == expected_class

    def test_create_decoder_invalid_type(self):
        """Test create_decoder with invalid decoder type."""
        with pytest.raises(ValueError) as excinfo:
            DecoderFactory.create_decoder("invalid")
        assert "Invalid decoder type: invalid" in str(excinfo.value)

    def test_decode_message(self, monkeypatch):
        """Test decode_message method (functional, not log output)."""
        # Mock the decoder.decode method
        mock_decoder = MagicMock()
        mock_decoder.decode.return_value = MagicMock()

        with patch.object(DecoderFactory, "create_decoder", return_value=mock_decoder):
            DecoderFactory.decode_message(
                "auto",
                "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick",
                enable_model_json_output=True,
            )

        # Verify the decoder was created and called correctly
        mock_decoder.decode.assert_called_once()
