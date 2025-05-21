# Ziggiz Courier Pickup Syslog

A syslog server for Ziggiz Courier pickup events that receives syslog messages over UDP, TCP, and Unix Stream protocols.

## Installation

```bash
pip install ziggiz-courier-pickup-syslog
```

## Usage

### Command Line

```bash
ziggiz-syslog [--config CONFIG_FILE] [--host HOST] [--protocol {tcp,udp,unix}] [--port PORT] [--unix-socket-path PATH] [--log-level {DEBUG,INFO,WARNING,ERROR,CRITICAL}]
```

### Configuration

The server can be configured using a YAML configuration file. By default, the server looks for a configuration file in the following locations:

1. `./config.yaml` (current directory)
2. `./config.yml` (current directory)
3. `/etc/ziggiz-courier-pickup-syslog/config.yaml`
4. `/etc/ziggiz-courier-pickup-syslog/config.yml`

You can also specify a configuration file with the `--config` option.

#### Example Configuration

```yaml
# Server configuration
host: "0.0.0.0"      # Host address to bind to (for TCP/UDP)
protocol: "tcp"      # Protocol to use: "tcp", "udp", or "unix"
port: 514            # TCP or UDP port to listen on (when using TCP/UDP protocols)
unix_socket_path: "/var/run/ziggiz-syslog.sock"  # Path for Unix socket (when using unix protocol)

# Logging configuration
log_level: "INFO"    # Root logger level: DEBUG, INFO, WARNING, ERROR, CRITICAL
log_format: "%(asctime)s %(levelname)s %(name)s %(message)s"
log_date_format: "%Y-%m-%d %H:%M:%S"

# Individual logger configurations
loggers:
  - name: "ziggiz_courier_pickup_syslog"
    level: "INFO"
    propagate: true

  - name: "ziggiz_courier_pickup_syslog.protocol.tcp"
    level: "DEBUG"
    propagate: true

# Decoder configuration
decoders:
  - type: "rfc5424"
    name: "standard_syslog"
    priority: 100
    parameters:
      parse_structured_data: true
```

#### Unix Socket Example Configuration

```yaml
# Server configuration using Unix Socket
protocol: "unix"     # Use Unix Socket protocol
unix_socket_path: "/var/run/ziggiz-syslog.sock"  # Path for Unix socket

# Logging configuration
log_level: "INFO"
log_format: "%(asctime)s %(levelname)s %(name)s %(message)s"
log_date_format: "%Y-%m-%d %H:%M:%S"
```

### Command Line Arguments

Command line arguments override the corresponding settings in the configuration file.

- `--config`: Path to the configuration file
- `--host`: Host address to bind to
- `--protocol`: Protocol to use (tcp, udp, unix)
- `--port`: TCP or UDP port to listen on
- `--unix-socket-path`: Path for Unix domain socket
- `--log-level`: Logging level
