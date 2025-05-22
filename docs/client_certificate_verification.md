# Client Certificate Verification

This document explains how to configure and use client certificate verification in the Ziggiz Courier Pickup Syslog server.

## Overview

Client certificate verification allows the server to authenticate clients based on their TLS certificates. This provides an additional layer of security beyond basic TLS encryption. The server can verify not only that the client's certificate is valid and trusted, but also that it contains specific attributes that match configurable patterns.

## Basic Certificate Verification

To enable basic client certificate verification:

1. Set `protocol` to `"tls"` in your configuration
2. Provide paths to your server certificate and key files
3. Provide a path to a CA certificate file that can verify client certificates
4. Set `tls_verify_client` to `true`

Example:

```yaml
protocol: "tls"
tls_certfile: "/path/to/server_cert.pem"
tls_keyfile: "/path/to/server_key.pem"
tls_ca_certs: "/path/to/ca_certs.pem"
tls_verify_client: true
```

With this configuration, the server will require clients to present a valid certificate that chains to one of the trusted CAs in the CA certificate file.

## Advanced Certificate Attribute Verification

For more granular control, you can configure rules to verify specific attributes in client certificates. This allows you to restrict access based on the Common Name (CN), Organizational Unit (OU), or other attributes in the certificate subject.

To configure certificate attribute verification:

1. Enable basic certificate verification as described above
2. Add `tls_cert_rules` to your configuration

Example:

```yaml
tls_cert_rules:
  - attribute: "CN"
    pattern: "client[0-9]+\\.example\\.com"
    required: true

  - attribute: "OU"
    pattern: "(DevOps|Operations)"
    required: true

  - attribute: "O"
    pattern: "Example Corp"
    required: false
```

### Rule Configuration

Each rule consists of:

- `attribute`: The certificate attribute to check (e.g., "CN", "OU", "O")
- `pattern`: A regular expression pattern that the attribute value must match
- `required`: Whether this attribute is required to be present (default: true)

All required attributes must be present in the certificate, and all attributes (required or optional) that are present must match their respective patterns for the certificate to be considered valid.

## Common Certificate Attributes

- `CN` (Common Name): Typically contains the hostname or domain name
- `OU` (Organizational Unit): Department or division within the organization
- `O` (Organization): Name of the organization
- `C` (Country): Two-letter country code
- `ST` (State/Province): State or province name
- `L` (Locality): City or locality name
- `emailAddress`: Email address of the certificate owner

## Logging

When client certificate verification is enabled, the server logs information about client certificates, including:

- Subject information (CN, OU, etc.)
- Issuer information
- Validity period
- Verification results

To see more detailed logs about certificate verification, set the log level for the relevant loggers to DEBUG:

```yaml
loggers:
  - name: "ziggiz_courier_pickup_syslog.protocol.tls"
    level: "DEBUG"
    propagate: true

  - name: "ziggiz_courier_pickup_syslog.protocol.cert_verify"
    level: "DEBUG"
    propagate: true
```

## Example Configuration

See the `config_with_cert_rules.yaml` file for a complete example configuration with certificate verification rules.

## Generating Test Certificates

For testing purposes, you can generate self-signed certificates using OpenSSL:

```bash
# Generate a CA key and certificate
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -subj "/CN=Test CA"

# Generate a server key and certificate signing request
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr -subj "/CN=server.example.com"

# Sign the server certificate with the CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt

# Generate a client key and certificate signing request
openssl genrsa -out client.key 2048
openssl req -new -key client.key -out client.csr -subj "/CN=client1.example.com/OU=DevOps/O=Example Corp"

# Sign the client certificate with the CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt
```

## Troubleshooting

If clients are being rejected unexpectedly:

1. Check the server logs for details about the certificate verification failure
2. Verify that the client certificate contains the required attributes
3. Test the regular expression patterns against the actual attribute values
4. Ensure the client certificate is signed by a CA that the server trusts
5. Check the certificate's validity period
