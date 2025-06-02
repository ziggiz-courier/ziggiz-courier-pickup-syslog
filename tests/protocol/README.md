# Protocol Tests Organization

## Test Hierarchy

The protocol test files are organized in a hierarchy to reflect the class hierarchy of the protocol implementations:

1. **Base Protocol Tests**:
   - `test_base_stream_protocol.py`
   - `test_base_stream_extended.py`

   These files test the core functionality in the `BaseSyslogBufferedProtocol` abstract base class, including:
   - Buffer management
   - Message framing and extraction
   - Connection handling
   - EOF handling
   - Error handling

2. **Specific Protocol Tests**:
   - `test_protocol_tcp.py` - TCP-specific functionality
   - `test_protocol_unix.py` - UNIX socket specific functionality
   - `test_protocol_tls.py` - TLS-specific functionality
   - `test_protocol_udp.py` - UDP functionality (different base class)

## Obsolete Tests

After the refactoring of the protocol hierarchy to move common functionality into the base class,
some tests in the protocol-specific test files became redundant with those in the base class tests.

The following tests in the protocol-specific files are now considered obsolete as they're fully covered
by base class tests:

**In TCP, TLS, and Unix protocol tests**:
- `test_get_buffer` - Tested in base class
- `test_eof_received` (basic functionality) - Tested in base class
- `test_connection_lost` - Tested in base class
- `test_buffer_updated` (basic functionality) - Tested in base class

## Test Maintenance Guidelines

1. **Base functionality changes**: When modifying functionality in the base class, update the base class tests.
2. **Protocol-specific changes**: When modifying protocol-specific functionality, update only the relevant protocol tests.
3. **Adding new protocol subclasses**: Create tests that focus on the unique aspects of the new protocol, and inherit base functionality testing from the base tests.

## Future Refactoring

At some point, the protocol-specific tests should be updated to remove redundant tests and focus solely on the protocol-specific functionality. The current tests are kept for backward compatibility until a thorough refactoring is done.
