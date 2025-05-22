# Configuration Examples

This directory contains example configuration files for the Ziggiz Courier Pickup Syslog server.

## Available Examples

1. **config_basic.yaml** - Basic TCP syslog server configuration
   - Uses TCP protocol on port 514
   - Auto framing mode
   - Auto decoder type

2. **config_udp.yaml** - UDP syslog server configuration
   - Uses UDP protocol on port 514
   - Auto framing mode
   - RFC 3164 decoder type (traditional BSD syslog format)

3. **config_unix.yaml** - Unix socket syslog server configuration
   - Uses Unix socket at `/var/run/ziggiz-syslog.sock`
   - Transparent framing mode
   - RFC 5424 decoder type (structured syslog format)

4. **config_unix_socket.yaml** - Alternative Unix socket configuration
   - Uses Unix socket at `/var/run/ziggiz-syslog.sock`
   - Non-transparent framing mode
   - RFC 5424 decoder type (structured syslog format)

5. **config_tls.yaml** - TLS syslog server configuration
   - Uses TLS protocol on port 6514
   - Basic TLS setup without client certificate verification
   - Auto framing mode
   - Auto decoder type

6. **config_tls_with_cert_rules.yaml** - TLS syslog server with certificate verification rules
   - Uses TLS protocol on port 6514
   - Client certificate verification with attribute matching rules
   - Non-transparent framing mode
   - RFC 5424 decoder type

7. **config_test.yaml** - Configuration for testing
   - Uses UDP protocol on non-privileged port 1514
   - Auto framing mode
   - Debug logging level
   - Useful for development and testing

## Usage

To use one of these configuration files, specify the path when starting the server:

```bash
python -m ziggiz_courier_pickup_syslog --config examples/config_basic.yaml
```

Or copy one of these files to the default location:

```bash
cp examples/config_basic.yaml config.yaml
python -m ziggiz_courier_pickup_syslog
```

## Configuration Options

For a complete list of configuration options and their descriptions, refer to the `Config` class in the `ziggiz_courier_pickup_syslog/config.py` file.
