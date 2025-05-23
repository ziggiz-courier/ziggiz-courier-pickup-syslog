# Ziggiz Courier Pickup Syslog Demo

This demo shows how to start the Ziggiz Courier Pickup Syslog server and send test messages to it using only bash commands.

## Prerequisites

- Python 3.8 or higher
- The `ziggiz-courier-pickup-syslog` package installed
- `netcat` (nc) command-line utility for sending test messages

## Running the Demo

The demo is split into two separate scripts:
1. `start_demo_server.sh` - Starts the syslog server with DEBUG logging
2. `send_demo_message.sh` - Sends test messages to the server

### Step 1: Start the Demo Server

In one terminal, start the server:

```bash
./examples/start_demo_server.sh
```

This script will:
- Start the syslog server with DEBUG logging level
- Listen on UDP port 5140
- Display all received and decoded messages
- **Show JSON representation of the decoded model** for each message

### Step 2: Send Test Messages

In another terminal, send test messages:

```bash
# Send an RFC5424 message (default)
./examples/send_demo_message.sh

# Send an RFC3164 message
./examples/send_demo_message.sh --type rfc3164

# Send a simple message
./examples/send_demo_message.sh --type simple
```

### Manual Message Sending

If you prefer to send messages manually using netcat:

```bash
# Simple message with current timestamp
echo '<13>Ziggiz Courier pickup event: Package #12345 picked up at '$(date '+%Y-%m-%d %H:%M:%S') | nc -u 127.0.0.1 5140

# RFC 3164 format message with current month/day
echo '<34>'$(date '+%b %d')' 22:14:15 myhost app[123]: This is a test message in RFC 3164 format' | nc -u 127.0.0.1 5140

# RFC 5424 format message with proper timestamp
echo '<165>1 '$(date -u '+%Y-%m-%dT%H:%M:%S.000Z')' '$(hostname -s)' ziggiz-courier '$$' PICKUP'$(date '+%s')' [exampleSDID@32473 iut="3"][ziggiz@32473 event="pickup" trackingId="PKG'$(date '+%s')'"] Courier package pickup notification' | nc -u 127.0.0.1 5140
```

## Understanding the Output

When you send a message to the server, you should see DEBUG-level log output showing:

1. The raw message received
2. The decoded message with parsed fields
3. A complete JSON representation of the decoded model
4. Any processing actions taken

For example, when sending an RFC 5424 message, you might see output like:

```bash
2025-05-23 09:00:50 DEBUG ziggiz_courier_pickup_syslog.protocol.udp Received UDP datagram
2025-05-23 09:00:50 DEBUG ziggiz_courier_pickup_syslog.protocol.decoder_factory Decoding syslog message - Extra: {
  "decoder_type": "auto",
  "has_connection_cache": true,
  "has_event_parsing_cache": true,
  "message_length": 241,
  "stack_info": null,
  "taskName": null
}
2025-05-23 09:00:50 INFO ziggiz_courier_pickup_syslog.protocol.decoder_factory Decoded model JSON representation: - Extra: {
  "decoded_model_json": {
    "timestamp": "2025-05-23T14:00:50Z",
    "event_time": null,
    "courier_timestamp": "2025-05-23T09:00:36.860518-05:00",
    "message": "Courier package pickup notification generated at 2025-05-23 09:00:50",
    "event_data": null,
    "handler_data": null,
    "facility": 20,
    "severity": 5,
    "hostname": "ryans-macbook-pro",
    "app_name": "ziggiz-courier",
    "proc_id": "95339",
    "msg_id": "PICKUP1748008850",
    "structured_data": {
      "exampleSDID@32473": {
        "iut": "3"
      },
      "ziggiz@32473": {
        "event": "pickup",
        "trackingId": "PKG1748008850"
      }
    }
  }
}
```

## Benefits of JSON Model Output

The enhanced JSON model output provides several benefits:

1. **Complete Data Representation**: The full decoded model is displayed in a standardized JSON format, making it easy to see all fields and values.

2. **Easy Integration**: The JSON output can be easily parsed by other tools and systems for further processing.

3. **Improved Debugging**: When troubleshooting issues, having the complete model representation helps identify missing or incorrect fields.

4. **Client Demo Support**: Demonstrates how clients can leverage the decoded data in their own applications.

## Configuration Details

The demo uses a configuration file (`demo_config.yaml`) with:

- UDP protocol on port 5140
- DEBUG logging level to show decoded messages
- Auto-detection of message formats
- Enhanced JSON model output display

You can modify this configuration to test different settings, such as:

- Changing to TCP protocol
- Using a Unix socket
- Enabling TLS
- Specifying a particular decoder type

## Troubleshooting

If you encounter issues:

1. Make sure nothing else is using port 5140
2. Check that you have the necessary permissions to bind to the port
3. Verify that netcat is installed and working correctly
4. Ensure the server is running before sending messages
