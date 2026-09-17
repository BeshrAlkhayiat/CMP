# EJBCA CMP Bridge - Proof of Concept

## Overview

This PoC demonstrates how to use `openssl cmp` to send certificate requests (IR or P10CR) to an internal EJBCA test CMP endpoint using the Siemens CMP RA Component.

## Architecture (Mode A - Pass-Through)

```
[OpenSSL CMP Client] 
        |
        | CMP over HTTP (port 8080)
        v
[EjbcaCmpBridge - RA Component]
        |
        | CMP over HTTP POST
        v
[EJBCA CMP Server]
```

The bridge acts as a **pass-through RA** (Mode A):
- Accepts CMP messages from OpenSSL on localhost:8080
- Forwards raw ASN.1-encoded CMP bytes to EJBCA via HTTP POST
- Returns EJBCA's response back to OpenSSL
- All CMP protocol handling is done by the RA Component

## Configuration Mapping

Based on your `CABackendParams-Kind-CMP.txt`:

| Parameter | Value | Location |
|-----------|-------|----------|
| `CMP.EndpointAddress` | EJBCA URL | Command line argument |
| `AuthenticationSharedSecret` | Shared secret | Command line argument |
| `CMP.Sender.KID` | Key ID | Command line argument |
| `CMP.HashAlgorithm` | SHA256 | Hardcoded in config |
| `CMP.ImplicitConfirm` | false | Hardcoded in config |
| `CMP.HashMinRounds` | 5000 | Hardcoded in config |
| `CMP.HashSaltSize` | 32 bytes | Hardcoded in config |
| `CMP.Dialect` | EJBCA | Handled automatically |

## Prerequisites

1. Java 11+
2. Bouncy Castle libraries (included in `cmp-ra-component/target/lib/`)
3. OpenSSL with CMP support (`openssl cmp` command)
4. Running EJBCA instance with CMP endpoint enabled

## Build

```bash
cd /workspace
javac -cp "cmp-ra-component/target/CmpRaComponent-4.3.0.jar:cmp-ra-component/target/lib/*" EjbcaCmpBridge.java
```

## Run

```bash
java -cp ".:cmp-ra-component/target/CmpRaComponent-4.3.0.jar:cmp-ra-component/target/lib/*" \
  EjbcaCmpBridge \
  "http://your-ejbca-server:8080/ejbca/publicweb/cmp/myalias" \
  "mySharedSecret" \
  "myKeyId"
```

Example output:
```
EJBCA CMP Bridge initialized
  EJBCA URL: http://your-ejbca-server:8080/ejbca/publicweb/cmp/myalias
  Downstream port: 8080
  Downstream path: /cmp
  Hash Algorithm: SHA256
  Implicit Confirm: false
  Hash Rounds: 5000
  Salt Size: 32 bytes

EJBCA CMP Bridge started on port 8080
Ready to accept CMP requests at http://localhost:8080/cmp

Example OpenSSL commands:
  # Initialize Request (IR):
  openssl cmp -server http://localhost:8080/cmp \
    -cacerts ejbca_ca.pem -certout cert.pem -keyout key.pem \
    -subject "/CN=TestUser/O=MyOrg" -ir \
    -secret mySharedSecret -kid myKeyId -digest sha256

  # PKCS#10 Certificate Request (P10CR):
  openssl cmp -server http://localhost:8080/cmp \
    -cacerts ejbca_ca.pem -certout issued_cert.pem \
    -p10cr user.csr \
    -secret mySharedSecret -kid myKeyId -digest sha256
```

## Usage with OpenSSL

### Option 1: Initialize Request (IR)

Generate a new key and request a certificate:

```bash
# First, export the CA certificate from EJBCA
openssl cmp -server http://localhost:8080/cmp \
  -cacerts ejbca_ca.pem \
  -subject "/CN=TestUser/O=MyOrg" \
  -ir \
  -secret mySharedSecret \
  -kid myKeyId \
  -digest sha256 \
  -certout cert.pem \
  -keyout key.pem
```

### Option 2: PKCS#10 Certificate Request (P10CR)

If you already have a CSR:

```bash
# Generate a key and CSR first
openssl genrsa -out user.key 2048
openssl req -new -key user.key -out user.csr -subj "/CN=TestUser/O=MyOrg"

# Submit the CSR via CMP
openssl cmp -server http://localhost:8080/cmp \
  -cacerts ejbca_ca.pem \
  -certout issued_cert.pem \
  -p10cr user.csr \
  -secret mySharedSecret \
  -kid myKeyId \
  -digest sha256
```

## How It Works

### 1. Downstream Interface (OpenSSL → Bridge)

- OpenSSL sends CMP message to `http://localhost:8080/cmp`
- Message is protected with MAC using shared secret
- RA Component validates the MAC protection
- Configuration: `getDownstreamConfiguration()`

### 2. Upstream Interface (Bridge → EJBCA)

- RA Component forwards the request via `UpstreamExchange.sendReceiveMessage()`
- Our implementation makes HTTP POST to EJBCA URL
- Request is reprotected with MAC for EJBCA
- Configuration: `getUpstreamConfiguration()`

### 3. Response Flow

- EJBCA returns CMP response
- Bridge forwards response to RA Component
- RA Component processes and validates response
- Response is sent back to OpenSSL

## Key Classes

### `EjbcaCmpBridge`
Main class that:
- Parses command-line arguments
- Creates RA Component instance
- Starts HTTP server on port 8080
- Forwards requests to EJBCA

### `EjbcConfiguration` (inner class)
Implements `Configuration` interface:
- Configures downstream (OpenSSL) interface
- Configures upstream (EJBCA) interface
- Sets MAC algorithm (HMAC-SHA256)
- Sets hash parameters (iterations, salt)

### `forwardToEjbca()` method
Implements `UpstreamExchange`:
- Makes HTTP POST to EJBCA
- Returns raw CMP response bytes
- Handles errors

## Troubleshooting

### "Connection refused"
Make sure EJBCA is running and the URL is correct.

### "MAC verification failed"
Check that the shared secret and KID match between OpenSSL, bridge, and EJBCA.

### "Certificate request rejected"
Check EJBCA logs for validation errors. The certificate profile may have restrictions.

### OpenSSL complains about CA certificates
Export the CA certificate chain from EJBCA first:
```bash
openssl cmp -server http://localhost:8080/cmp \
  -cacerts ca_certs.pem \
  -genm \
  -secret mySharedSecret \
  -kid myKeyId
```

## Security Considerations

⚠️ **This is a PoC - not production ready!**

For production:
1. Use TLS between bridge and EJBCA (HTTPS)
2. Implement proper secret management (not command-line args)
3. Add logging and monitoring
4. Implement rate limiting
5. Consider using signature-based protection instead of MAC
6. Add certificate validation for EJBCA responses
7. Implement proper error handling and retry logic

## Next Steps

1. Test with your EJBCA instance
2. Adjust configuration as needed (hash algorithm, timeouts, etc.)
3. Add TLS support for upstream connection
4. Implement secret lookup by KID for multiple clients
5. Add metrics and logging
6. Consider adding persistence for polling support

## References

- [Siemens CMP RA Component Documentation](../README.md)
- [Lightweight CMP Profile](https://tools.ietf.org/wg/lamps/draft-ietf-lamps-lightweight-cmp-profile/)
- [EJBCA CMP Documentation](https://www.ejbca.org/docs)
- [OpenSSL CMP Documentation](https://www.openssl.org/docs/man3.0/man1/openssl-cmp.html)
