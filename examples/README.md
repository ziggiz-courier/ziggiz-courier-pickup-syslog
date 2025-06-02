# Configuration Examples


# Configuration Examples

# Overview

This directory contains example configuration files for the Ziggiz Courier Pickup Syslog server. Each file demonstrates a different deployment scenario or protocol supported by the server. Use these as templates for your own deployments or for testing/demo purposes.


## Available Example Configurations

# List of Example Configurations


1. **config_basic.yaml**
   - Basic TCP syslog server configuration
   - Uses TCP protocol on port 514
   - Auto framing mode (detects message boundaries automatically)
   - Auto decoder type (detects syslog message format automatically)

2. **config_udp.yaml**
   - UDP syslog server configuration
   - Uses UDP protocol on port 514
   - Auto framing mode
   - RFC 3164 decoder type (traditional BSD syslog format)

3. **config_unix.yaml**
   - Unix socket syslog server configuration
   - Uses Unix socket at `/var/run/ziggiz-syslog.sock`
   - Transparent framing mode (octet-counted messages)
   - RFC 5424 decoder type (structured syslog format)

4. **config_unix_socket.yaml**
   - Alternative Unix socket configuration
   - Uses Unix socket at `/var/run/ziggiz-syslog.sock`
   - Non-transparent framing mode (delimiter-based)
   - RFC 5424 decoder type (structured syslog format)

5. **config_tls.yaml**
   - TLS syslog server configuration
   - Uses TLS protocol on port 6514
   - Basic TLS setup without client certificate verification
   - Auto framing mode
   - Auto decoder type

6. **config_tls_with_cert_rules.yaml**
   - TLS syslog server with certificate verification rules
   - Uses TLS protocol on port 6514
   - Client certificate verification with attribute matching rules
   - Non-transparent framing mode
   - RFC 5424 decoder type

7. **config_test.yaml**
   - Configuration for testing
   - Uses UDP protocol on non-privileged port 1514
   - Auto framing mode
   - Debug logging level (for development and testing)


## Usage Instructions

# How to Use Example Configurations


To use one of these configuration files, specify the path to the config file when starting the server. For example:


```bash
python -m ziggiz_courier_pickup_syslog --config examples/config_basic.yaml
```


Alternatively, you can copy one of these files to the default location (`config.yaml`) in your project root:


```bash
cp examples/config_basic.yaml config.yaml
python -m ziggiz_courier_pickup_syslog
```


## Configuration Options Reference

For a complete list of configuration options and their descriptions, refer to the `Config` class in the [`ziggiz_courier_pickup_syslog/config.py`](../ziggiz_courier_pickup_syslog/config.py) file. Each option is documented with its type, default value, and description in the codebase.

---

<!--
This README is intended to help users quickly understand the available example configurations and how to use them. For more details on configuration fields, see the main project README and the config.py source file.
-->
