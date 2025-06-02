# -*- coding: utf-8 -*-

# SPDX-License-Identifier: BSL-1.1
# Copyright (c) 2025 Ziggiz Inc.
#
# This file is part of the ziggiz-courier-core-data-processing and is licensed under the
# Business Source License 1.1. You may not use this file except in
# compliance with the License. You may obtain a copy of the License at:
# https://github.com/ziggiz-courier/ziggiz-courier-core-data-processing/blob/main/LICENSE
# __main__ module to support python -m ziggiz_courier_pickup_syslog
#
# This allows the package to be run as a module using `python -m ziggiz_courier_pickup_syslog`.
# It simply calls the main entry point.

# Local/package imports
from ziggiz_courier_pickup_syslog.main import main

if __name__ == "__main__":
    main()
