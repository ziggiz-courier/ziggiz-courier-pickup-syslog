# -*- coding: utf-8 -*-
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
# OpenTelemetry setup for Ziggiz Courier Pickup Syslog
#
# This module configures OpenTelemetry tracing for the syslog server.
# By default, it exports spans to the console for development/demo purposes.
# In production, configure an OTLP exporter via environment variables.

# Third-party imports
from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.trace import Tracer

# Create an OpenTelemetry resource for the service
resource = Resource.create({"service.name": "ziggiz-courier-pickup-syslog"})
tracer_provider = TracerProvider(resource=resource)
trace.set_tracer_provider(tracer_provider)

# For demo/dev: export to console. Replace with OTLPSpanExporter for production.
span_processor = BatchSpanProcessor(ConsoleSpanExporter())
tracer_provider.add_span_processor(span_processor)


def get_tracer() -> Tracer:
    return trace.get_tracer("ziggiz-courier-pickup-syslog")
