#!/bin/bash

# Ziggiz Courier Pickup Syslog Demo Message Sender
# This script sends test syslog messages to the demo server

# Default values
HOST="127.0.0.1"
PORT=5140
MESSAGE_TYPE="rfc5424"  # Default to RFC5424 format

# Define colors for better readability
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Help function
function show_help {
    echo -e "${BLUE}Usage:${NC} $0 [options]"
    echo
    echo "Options:"
    echo "  -h, --host HOST      Host address (default: 127.0.0.1)"
    echo "  -p, --port PORT      Port number (default: 5140)"
    echo "  -t, --type TYPE      Message type: rfc3164, rfc5424, simple (default: rfc5424)"
    echo "  --help               Show this help message"
    echo
    echo "Example:"
    echo "  $0 --type rfc3164"
    exit 0
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -h|--host)
            HOST="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -t|--type)
            MESSAGE_TYPE="$2"
            shift 2
            ;;
        --help)
            show_help
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            show_help
            ;;
    esac
done

# Check if netcat is available
if ! command -v nc &> /dev/null; then
    echo -e "${RED}Error: netcat (nc) is not installed.${NC}"
    echo "Please install netcat to use this script."
    exit 1
fi

# Check if the server is running
if ! nc -z $HOST $PORT 2>/dev/null; then
    echo -e "${YELLOW}Warning: No server detected at ${HOST}:${PORT}.${NC}"
    echo -e "Make sure the server is running (use ./examples/start_demo_server.sh)"
    echo -e "Continue anyway? (y/n)"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Prepare the message based on type
case $MESSAGE_TYPE in
    rfc3164)
        # RFC 3164 (BSD) format - using current month/day but fixed time for consistency
        MONTH=$(date '+%b')
        DAY=$(date '+%d')
        MESSAGE="<34>$MONTH $DAY 22:14:15 myhost app[123]: This is a test message in RFC 3164 format"
        ;;
    rfc5424)
        # RFC 5424 format with properly generated timestamp
        # Format: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        # Generate RFC5424 compliant timestamp (YYYY-MM-DDThh:mm:ss.sssZ)
        TIMESTAMP=$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')
        HOSTNAME=$(hostname -s 2>/dev/null || echo "myhost")
        PRIORITY="<165>"  # Facility 20 (local4), Severity 5 (Notice)
        VERSION="1"
        APPNAME="ziggiz-courier"
        PROCID="$$"  # Use current script's PID
        MSGID="PICKUP$(date '+%s')"  # Unique message ID using timestamp
        STRUCTURED_DATA="[exampleSDID@32473 iut=\"3\"][ziggiz@32473 event=\"pickup\" trackingId=\"PKG$(date '+%s')\"]"
        MESSAGE_TEXT="Courier package pickup notification generated at $(date '+%Y-%m-%d %H:%M:%S')"

        # Construct the full RFC5424 message
        MESSAGE="$PRIORITY$VERSION $TIMESTAMP $HOSTNAME $APPNAME $PROCID $MSGID $STRUCTURED_DATA $MESSAGE_TEXT"
        ;;
    simple|*)
        # Simple format
        MESSAGE="<13>Ziggiz Courier pickup event: Package #12345 picked up at $(date '+%Y-%m-%d %H:%M:%S')"
        ;;
esac

echo -e "${BLUE}Sending test message to ${HOST}:${PORT}...${NC}"
echo -e "${YELLOW}Message type:${NC} $MESSAGE_TYPE"
echo -e "${YELLOW}Message:${NC} $MESSAGE"

# Send the message
echo "$MESSAGE" | nc -u "$HOST" "$PORT"

# Check if the message was sent successfully
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Message sent successfully!${NC}"
    echo -e "${BLUE}Check the server output to see the decoded message.${NC}"
else
    echo -e "${RED}Failed to send message.${NC}"
    echo "Make sure the server is running and the host/port are correct."
    exit 1
fi
