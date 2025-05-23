# UDP Fragmentation Handling

This document describes how the Ziggiz Courier Syslog Server handles UDP packet fragmentation.

## Overview

When UDP datagrams exceed the Maximum Transmission Unit (MTU) size of a network (typically 1500 bytes minus IP and UDP headers), the IP layer fragments them into multiple smaller packets. These packets must be reassembled at the destination before being delivered to the application layer.

## Implementation

The Ziggiz Courier Syslog Server includes features to properly handle UDP fragmentation:

1. **Socket Buffer Size Configuration**
   - The `udp_buffer_size` parameter in the configuration controls the socket receive buffer size
   - This buffer size is configured when a UDP connection is established
   - The default size is 65536 bytes (64KB), but can be increased for large messages
   - Example configuration:
   ```yaml
   host: "::"
   protocol: "udp"
   port: 514
   udp_buffer_size: 131072  # Increase to 128KB for very large messages
   ```

2. **IP-Layer Reassembly**
   - The actual reassembly of fragments happens at the IP layer, below the application
   - When properly configured, the operating system assembles fragments and delivers complete datagrams to our application
   - Our UDP protocol implementation is designed to handle these reassembled datagrams correctly

## Potential Issues

UDP fragmentation can face several challenges:

1. **Network Devices Blocking Fragments**
   - Some firewalls or routers may block IP fragments for security reasons
   - Solution: Configure network devices to allow fragmented UDP packets

2. **Fragment Loss**
   - If any fragment is lost, the entire datagram must be retransmitted
   - Solution: Prefer TCP for mission-critical or large messages

3. **Buffer Size Limitations**
   - If a reassembled datagram exceeds the socket buffer size, it may be truncated
   - Solution: Increase `udp_buffer_size` in your configuration

## Recommendations

For optimal handling of large syslog messages:

- Use TCP or TLS transport when possible for messages that might exceed MTU size
- If UDP is required, configure a sufficiently large `udp_buffer_size`
- Keep syslog messages under 1400 bytes to avoid fragmentation when possible
- Consider enabling Path MTU Discovery in your network
- Ensure that firewalls and security devices are configured to allow UDP fragments

## Monitoring

The syslog server logs the actual UDP buffer size when a connection is made. Check the logs at DEBUG level to verify that the buffer size was set correctly:

```
UDP receive buffer size configured: requested_size=65536, actual_size=262144
```

Note that some operating systems may increase the buffer size beyond what was requested for performance reasons.
