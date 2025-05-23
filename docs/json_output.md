# JSON Model Output Feature

## Overview

The Ziggiz Courier Pickup Syslog server now supports conditional JSON output of decoded syslog messages. This feature is designed to provide a detailed view of parsed syslog messages in structured format, particularly useful during development, debugging, and demonstrations.

## Configuration

JSON model output is controlled by the `enable_model_json_output` configuration option. By default, this option is set to `false` to optimize performance in production environments. When enabled, the server will output a JSON representation of each decoded syslog message alongside the regular processing.

### Setting the Configuration

In your configuration YAML file:

```yaml
# Enable JSON model output (recommended for demo/development only)
enable_model_json_output: true
```

The `enable_model_json_output` parameter has been added to:
- Configuration class
- Protocol handlers (UDP, TCP, Unix, TLS)
- DecoderFactory's decode_message method

## Usage

When enabled, the JSON model output appears in the logs alongside the regular message processing. This provides a complete representation of the decoded message structure and all parsed fields.

### Example Output

With JSON model output enabled, you'll see additional output in your logs similar to:

```
2023-08-15 14:30:22,123 INFO [ziggiz_courier_pickup_syslog.protocol.udp] Syslog message received {"msg_type": "RFC5424Message", "host": "192.168.1.10", "port": 54321, "log_msg": "<34>1 2023-08-15T14:30:22.000Z example-host example-app - - [exampleSDID@32473 foo=\"bar\"] This is a test message"}
2023-08-15 14:30:22,124 INFO [ziggiz_courier_pickup_syslog.protocol.decoder_factory] Message model: {"version": 1, "severity": 2, "facility": 4, "timestamp": "2023-08-15T14:30:22.000Z", "hostname": "example-host", "app_name": "example-app", "proc_id": null, "msg_id": null, "structured_data": {"exampleSDID@32473": {"foo": "bar"}}, "message": "This is a test message"}
```

## Performance Considerations

The JSON model output feature has a performance impact, as it requires additional processing to serialize the message models to JSON. For production environments where maximum throughput is required, it's recommended to keep this feature disabled.

## Use Cases

- **Debugging**: Understand exactly how messages are being parsed and interpreted
- **Development**: Validate that your syslog messages are formatted correctly
- **Demonstrations**: Show the full structure of parsed messages for educational purposes
- **Testing**: Verify that all expected fields are correctly extracted

## Recommendation

Enable this feature only in development, testing, or demonstration environments. For production deployments, keep it disabled to maintain optimal performance.
