# Ziggiz Courier Pickup Syslog

[![CI](https://github.com/ziggiz-courier/ziggiz-courier-pickup-syslog/actions/workflows/ci.yml/badge.svg)](https://github.com/ziggiz-courier/ziggiz-courier-pickup-syslog/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/ziggiz-courier/ziggiz-courier-pickup-syslog/branch/main/graph/badge.svg)](https://codecov.io/gh/ziggiz-courier/ziggiz-courier-pickup-syslog)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/downloads/release/python-3130/)

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
3. `./examples/config_basic.yaml` (examples directory)
4. `/etc/ziggiz-courier-pickup-syslog/config.yaml`
5. `/etc/ziggiz-courier-pickup-syslog/config.yml`

You can also specify a configuration file with the `--config` option.

Several example configuration files are provided in the `examples/` directory for different use cases:
- `config_basic.yaml`: Basic TCP syslog server
- `config_udp.yaml`: UDP syslog server
- `config_unix.yaml`: Unix socket server with transparent framing
- `config_unix_socket.yaml`: Unix socket server with non-transparent framing
- `config_tls.yaml`: Basic TLS syslog server
- `config_tls_with_cert_rules.yaml`: TLS server with certificate verification
- `config_test.yaml`: Configuration for testing with debug logging

#### Example Configuration

```yaml
# Server configuration
host: "0.0.0.0"      # Host address to bind to (for TCP/UDP)
protocol: "tcp"      # Protocol to use: "tcp", "udp", or "unix"
port: 514            # TCP or UDP port to listen on (when using TCP/UDP protocols)
unix_socket_path: "/var/run/ziggiz-syslog.sock"  # Path for Unix socket (when using unix protocol)

# Framing configuration
framing_mode: "auto"  # Message framing mode: "auto", "transparent", or "non_transparent"
end_of_message_marker: "\\n"  # End of message marker for non-transparent framing (supports escape sequences)
max_message_length: 16384     # Maximum message length in bytes for non-transparent framing

# Decoder configuration
decoder_type: "auto"  # Syslog decoder type: "auto", "rfc3164", "rfc5424", or "base"

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

### Message Framing Modes

The server supports different framing modes for TCP and Unix Stream protocols:

- **auto**: Automatically detects the framing mode for each message. First checks if the message starts with an octet count followed by a space (transparent framing), and if not, assumes non-transparent framing. Allows mixed framing types in the same connection.
- **transparent**: Expects octet-counting framing as described in RFC 5425 (TLS Transport Mapping for Syslog). Each message must be prefixed with a decimal count of its bytes, followed by a space. For example: `11 Hello World`. The octet count must be between 1-5 digits (no leading zeros).
- **non_transparent**: Uses a delimiter character(s) to separate messages. By default, this is a newline (`\n`), but can be configured with `end_of_message_marker`.

The `end_of_message_marker` supports common escaped sequences like `\\n` (newline), `\\r\\n` (carriage return + newline), `\\0` (null), as well as hex codes like `\\x00`.

### Syslog Decoders

The server supports different decoder types for parsing syslog messages. Each decoder is optimized for specific syslog message formats:

- **auto**: Uses the `UnknownSyslogDecoder` that automatically tries all available decoder formats to parse messages. This is the default and most flexible option, but less efficient as it may need to try multiple formats for each message.
- **rfc3164**: Uses the `SyslogRFC3164Decoder` specifically for RFC 3164 formatted syslog messages (BSD syslog format). Example: `<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8`
- **rfc5424**: Uses the `SyslogRFC5424Decoder` specifically for RFC 5424 formatted syslog messages (newer, structured format). Example: `<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - - %% It's time to make the do-nuts.`
- **base**: Uses the `SyslogRFCBaseDecoder` for basic syslog parsing with minimal format validation.

#### Performance Considerations

- For high volume environments with known message formats, specify the exact decoder type for better performance.
- The "auto" option is convenient but consumes more CPU cycles as it tries multiple parsers.
- For mixed message environments where you can't predict the format, "auto" is still the best choice.

#### Thread Safety

Decoders are instantiated per-connection to ensure thread safety, as they maintain connection-specific caches. This ensures that:

- Each TCP connection gets its own decoder instance
- Each UDP client (identified by source address) gets its own decoder instance
- Each Unix socket connection gets its own decoder instance

#### Configuration Examples

For RFC 3164 (BSD) formatted messages:
```yaml
decoder_type: "rfc3164"
```

For RFC 5424 (modern) formatted messages:
```yaml
decoder_type: "rfc5424"
```

For mixed environments:
```yaml
decoder_type: "auto"  # Default
```

### Command Line Arguments

Command line arguments override the corresponding settings in the configuration file.

- `--config`: Path to the configuration file
- `--host`: Host address to bind to
- `--protocol`: Protocol to use (tcp, udp, unix)
- `--port`: TCP or UDP port to listen on
- `--unix-socket-path`: Path for Unix domain socket
- `--framing-mode`: Framing mode (auto, transparent, non_transparent)
- `--end-of-message-marker`: End of message marker for non-transparent framing
- `--max-message-length`: Maximum message length in bytes for non-transparent framing
- `--decoder-type`: Syslog decoder type (auto, rfc3164, rfc5424, base)
- `--log-level`: Logging level

## Development

### Prerequisites

- Python 3.13
- Poetry for dependency management

### Setup Development Environment

```bash
# Clone the repository
git clone https://github.com/ziggiz-courier/ziggiz-courier-pickup-syslog.git
cd ziggiz-courier-pickup-syslog

# Install dependencies with Poetry
poetry install

# Activate the virtual environment
poetry shell
```

### Running Tests

```bash
# Run tests with pytest
pytest

# Run tests with coverage
pytest --cov=ziggiz_courier_pickup_syslog

# Run tests with tox (all environments)
tox
```

### Code Quality

The project uses several tools to ensure code quality:

- **Black**: Code formatter
- **isort**: Import sorter
- **Flake8**: Linter
- **MyPy**: Static type checker

You can run these tools using tox:

```bash
# Run linters
tox -e lint

# Run type checking
tox -e mypy
```

### Continuous Integration

This project uses GitHub Actions for continuous integration. The CI pipeline:

1. Runs tests on Python 3.13
2. Runs linters (black, isort, flake8)
3. Runs type checking with mypy
4. Generates and uploads test coverage to Codecov

The CI workflow is triggered on:
- Push to main/master branch
- Pull requests to main/master branch
