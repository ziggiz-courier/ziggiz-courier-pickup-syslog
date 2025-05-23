#!/bin/bash

# Ziggiz Courier Pickup Syslog Demo Server
# This script starts the syslog server with DEBUG logging for demonstration purposes

# Define colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Ziggiz Courier Pickup Syslog Demo Server ===${NC}"
echo -e "${BLUE}This script will start the syslog server with DEBUG logging${NC}"
echo

# Check if the server is already running on the demo port
if nc -z localhost 5140 2>/dev/null; then
    echo -e "${RED}Error: Something is already running on port 5140.${NC}"
    echo -e "Please stop any existing services on this port before continuing."
    exit 1
fi

# Path to the demo configuration
CONFIG_PATH="./examples/demo_config.yaml"

# OTel/Jaeger environment variables
export OTEL_TRACES_EXPORTER=otlp
export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
export OTEL_EXPORTER_OTLP_PROTOCOL="http/protobuf"
export OTEL_SERVICE_NAME="ziggiz-courier-pickup-syslog-demo"
export OTEL_RESOURCE_ATTRIBUTES="service.version=demo"

echo -e "${BLUE}Starting the syslog server...${NC}"
echo -e "Using configuration: ${CONFIG_PATH}"
echo -e "The server will listen on TCP port 5140"
echo

# Highlight the JSON model output feature
echo -e "${GREEN}Demo Features:${NC}"
echo -e "• Complete ${YELLOW}JSON representation${NC} of decoded models will be displayed"
echo -e "• All received messages will show as structured data"
echo -e "• This demonstrates our refactored solution with enhanced output"
echo

# Start the server in the foreground
echo -e "${YELLOW}Server is starting. Press Ctrl+C to stop.${NC}"
echo -e "${BLUE}To send test messages, run ./examples/send_demo_message.sh in another terminal.${NC}"
echo

# Start the server
exec python -m ziggiz_courier_pickup_syslog --config "$CONFIG_PATH"
