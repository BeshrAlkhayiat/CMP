# CMP RA Component with REST API Upstream - Complete Guide

## Overview

This guide explains how to use the Siemens CMP RA component to build a Registration Authority (RA) that:
- **Accepts CMP requests from end entities** (hosts, devices, applications)
- **Communicates with your CA via REST API** (not CMP)
- **Handles all CMP protocol complexity** automatically

## Architecture

```
┌─────────────┐      CMP (ASN.1 DER)      ┌──────────────────┐    REST API (JSON)    ┌──────────┐
│ End Entity  │ ◄──────────────────────► │   Your RA        │ ◄──────────────────► │   CA     │
│ (Host)      │                          │   Application    │                      │ System   │
└─────────────┘                          └──────────────────┘                      └──────────┘
                                         │                  │
                                         │  CMP RA          │
                                         │  Component       │
                                         │                  │
                                         │  ┌────────────┐  │
                                         │  │Upstream    │  │
                                         │  │Exchange    │  │
                                         │  │(REST API)  │  │
                                         │  └────────────┘  │
                                         └──────────────────┘
```

## Key Design Principles

### 1. Single Downstream, Single Upstream Interface

The CMP RA component provides:
- **One downstream interface** towards end entities (CMP protocol)
- **One upstream interface** towards the CA (you implement this)

If you need multiple interfaces:
- **Transport/routing differentiation**: Handle in your application by multiplexing channels
- **Message protection/behavior differentiation**: Use certificate profiles
- **Different CMP processing**: Create multiple RA instances

### 2. ASN.1 DER Byte String Exchange

All messages are exchanged as **opaque ASN.1 DER-encoded byte strings**:
- Your transport layer doesn't need to parse message contents
- Simply forward bytes between interfaces
- Avoids error-prone Java class handling

### 3. Transport Layer Responsibilities

Your embedding application handles:

**Downstream (from clients):**
```java
// 1. Extract request from HTTP/MQTT/etc.
byte[] requestBytes = httpServer.extractBody();

// 2. Feed to RA component
byte[] responseBytes = raComponent.processRequest(requestBytes);

// 3. Return response to client
httpServer.sendResponse(responseBytes);
```

**Upstream (to CA):**
```java
// Implemented in your UpstreamExchange:
// 1. Receive CMP request bytes from RA component
// 2. Convert to REST API call
// 3. Get REST response
// 4. Convert back to CMP response bytes
// 5. Return to RA component
```

## Implementation Steps

### Step 1: Implement Configuration

Create a class implementing `Configuration` interface:

```java
class RestApiConfiguration implements Configuration {
    
    @Override
    public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
        // Configure how to protect messages TO end entities
        return new CmpMessageInterface() {
            @Override
            public ProtectionMode getProtectionMode() {
                return ProtectionMode.SIGNATURE;
            }
            
            @Override
            public KeyStore getCredentialStore() {
                return loadRaCredentials(); // RA's signing cert + key
            }
        };
    }
    
    @Override
    public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
        // Return NULL - we're using REST API, not CMP upstream!
        return null;
    }
    
    @Override
    public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
        // CA trust anchors for verifying issued certificates
        return new VerificationContext() {
            @Override
            public KeyStore getTrustAnchorStore() {
                return loadCaRootCerts();
            }
        };
    }
    
    // ... implement other methods (see full example)
}
```

### Step 2: Implement UpstreamExchange with REST API

This is where you convert CMP ↔ REST:

```java
class RestApiUpstreamExchange implements UpstreamExchange {
    
    private final String caApiUrl;
    private final HttpClient httpClient;
    
    @Override
    public byte[] sendReceiveMessage(byte[] cmpRequest, String certProfile, int bodyType) {
        
        // 1. Parse CMP request (extract CSR, sender info, etc.)
        CmpRequestData data = parseCmpRequest(cmpRequest);
        
        // 2. Build REST API payload
        String jsonPayload = buildJsonPayload(data, certProfile);
        
        // 3. Call CA REST API
        String restResponse = callRestApi(jsonPayload);
        
        // 4. Convert REST response to CMP response
        byte[] cmpResponse = buildCmpResponse(restResponse, cmpRequest);
        
        return cmpResponse;
    }
}
```

### Step 3: Instantiate and Use the RA Component

```java
public static void main(String[] args) throws Exception {
    
    // Create configuration
    Configuration config = new RestApiConfiguration();
    
    // Create upstream exchange
    UpstreamExchange upstream = new RestApiUpstreamExchange(
        "https://ca.example.com/api/certificates",
        "api-key"
    );
    
    // Instantiate RA component
    CmpRaInterface ra = CmpRaComponent.instantiateCmpRaComponent(config, upstream);
    
    // Process requests from end entities
    byte[] cmpRequest = receiveFromHost();  // From HTTP/MQTT/etc.
    byte[] cmpResponse = ra.processRequest(cmpRequest);
    sendToHost(cmpResponse);
}
```

## Message Flow Example

### Certificate Request (CR/CP) Flow:

```
1. End Entity → RA: CMP CR (Certification Request)
   [ASN.1 DER encoded PKIMessage with bodyType=2]

2. RA Component processes:
   - Validates message signature
   - Checks inventory/authorization
   - Extracts certificate profile
   - Calls UpstreamExchange.sendReceiveMessage()

3. UpstreamExchange converts:
   - Parses CMP CR to extract CSR
   - Builds JSON: {"csr": "MIIC...", "profile": "web-server"}
   - POSTs to CA REST API

4. CA REST API responds:
   - Returns JSON: {"certificate": "MIID...", "status": "issued"}

5. UpstreamExchange converts back:
   - Parses REST response
   - Builds CMP CP (Certification Response) with certificate
   - Signs with RA credentials
   - Returns DER-encoded CMP response

6. RA Component → End Entity: CMP CP
   [ASN.1 DER encoded PKIMessage with issued cert]
```

## Body Types Reference

| Body Type | Request | Response | Description |
|-----------|---------|----------|-------------|
| 0 | IR | IP | Initial Request/Response |
| 2 | CR | CP | Certification Request/Response |
| 7 | KUR | KUP | Key Update Request/Response |
| 11 | RR | RRP | Revocation Request/Response |
| 21 | GENM | GENP | General Message/Response |

## REST API Integration Patterns

### Pattern 1: Simple Certificate Issuance

```java
private byte[] buildCmpResponse(String restResponse, byte[] originalRequest, int bodyType) {
    // Parse REST response
    JsonNode response = objectMapper.readTree(restResponse);
    String certBase64 = response.get("certificate").asText();
    
    // Decode certificate
    byte[] certDer = Base64.getDecoder().decode(certBase64);
    X509Certificate cert = parseCertificate(certDer);
    
    // Build CMP CP/IP/KUP response with certificate
    PKIBody responseBody = buildCertResponse(cert, bodyType);
    
    // Build complete PKIMessage with matching transaction ID
    PKIMessage cmpResponse = buildPkiMessage(originalRequest, responseBody);
    
    return cmpResponse.getEncoded();
}
```

### Pattern 2: Asynchronous Processing (Polling)

If your CA takes time to issue certificates:

```java
@Override
public byte[] sendReceiveMessage(byte[] cmpRequest, String certProfile, int bodyType) {
    
    // Submit request to CA
    String requestId = submitToCa(cmpRequest, certProfile);
    
    // Check if ready immediately
    if (isReady(requestId)) {
        return buildCmpResponse(fetchCertificate(requestId), cmpRequest, bodyType);
    } else {
        // Return null to trigger delayed delivery (polling)
        // Store requestId in persistency for later retrieval
        storePendingRequest(requestId, cmpRequest);
        return null;
    }
}
```

### Pattern 3: Error Handling

```java
@Override
public byte[] sendReceiveMessage(byte[] cmpRequest, String certProfile, int bodyType) 
        throws Exception {
    
    try {
        // Call REST API
        HttpResponse<String> response = httpClient.send(request, ...);
        
        if (response.statusCode() == 400) {
            throw new Exception("Invalid request: " + response.body());
        } else if (response.statusCode() == 403) {
            throw new Exception("Authorization failed");
        } else if (response.statusCode() != 200) {
            throw new Exception("CA error: " + response.statusCode());
        }
        
        return buildCmpResponse(response.body(), cmpRequest, bodyType);
        
    } catch (IOException e) {
        throw new Exception("Network error calling CA: " + e.getMessage());
    }
}
```

## Configuration Options

### Certificate Profiles

Use profiles to differentiate behavior:

```yaml
# In your configuration
certProfiles:
  web-server:
    downstreamProtection: SIGNATURE
    upstreamProfile: web-cert
  iot-device:
    downstreamProtection: MAC
    upstreamProfile: device-cert
```

Extracted from CMP request header `generalInfo` field:
```java
String profile = certProfile; // Passed to all configuration methods
```

### Message Protection Modes

**Downstream options:**
- `SIGNATURE` - Signature-based (recommended)
- `MAC` - MAC-based (shared secret)
- `CERT_ONLY` - No protection, just certificate

**Upstream:** Not used when implementing REST API exchange

### Trust Anchors

Configure which CAs you trust:
```java
@Override
public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
    return new VerificationContext() {
        @Override
        public KeyStore getTrustAnchorStore() {
            // Load CA root certificates
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("ca-trust.jks"), password);
            return ks;
        }
    };
}
```

## Deployment Considerations

### Security

1. **Protect RA credentials**: Store in HSM or secure keystore
2. **Validate REST API responses**: Verify CA signatures on certificates
3. **Authenticate end entities**: Require signature-based POPO
4. **Secure transport**: Use HTTPS/TLS for both downstream and upstream

### Performance

1. **Connection pooling**: Reuse HTTP clients for REST calls
2. **Async processing**: Use polling for long-running operations
3. **Caching**: Cache trust anchors and configurations

### High Availability

1. **Stateless design**: Store state in external database
2. **Multiple instances**: Load balance across RA instances
3. **Persistence**: Implement `PersistencyInterface` for transaction recovery

### Monitoring

1. **Log all transactions**: Include transaction IDs for tracing
2. **Metrics**: Track request rates, error rates, latency
3. **Alerts**: Monitor CA API availability

## Complete Working Example

See `CmpRaWithRestUpstream.java` for a full implementation including:
- Complete Configuration implementation
- REST API UpstreamExchange
- CMP parsing and response building helpers
- Credential loading examples

## Testing

### Unit Test Your UpstreamExchange

```java
@Test
public void testRestApiConversion() throws Exception {
    // Create test CMP request
    byte[] cmpRequest = createTestCmpCr();
    
    // Mock REST API
    RestApiUpstreamExchange exchange = new RestApiUpstreamExchange(mockApiUrl, "key");
    
    // Test conversion
    byte[] cmpResponse = exchange.sendReceiveMessage(cmpRequest, "test-profile", 2);
    
    // Verify response structure
    assertNotNull(cmpResponse);
    PKIMessage response = PKIMessage.getInstance(ASN1Primitive.fromByteArray(cmpResponse));
    assertEquals(3, response.getBody().getType()); // CP response
}
```

### Integration Test Full Flow

```java
@Test
public void testEndToEnd() throws Exception {
    // Setup RA component with mock CA
    CmpRaInterface ra = setupRaWithMockCa();
    
    // Send CMP request
    byte[] request = createCmpCr();
    byte[] response = ra.processRequest(request);
    
    // Verify CMP response contains certificate
    PKIMessage pkiMsg = parseResponse(response);
    CertRepMessage certRep = CertRepMessage.getInstance(pkiMsg.getBody().getContent());
    assertNotNull(certRep.getCertRepContent().getCertResponse()[0].getCertifiedKeyPair());
}
```

## Troubleshooting

### Common Issues

**"Upstream configuration is null"**
- Expected when using REST API upstream
- Ensure `getUpstreamConfiguration()` returns null intentionally

**"Cannot build CMP response"**
- You need to properly construct PKIMessage with BouncyCastle
- Match transaction ID from request
- Sign with downstream credentials

**"Certificate verification failed"**
- Check trust anchor configuration
- Ensure CA chain is complete

**"Timeout on downstream"**
- Increase `getDownstreamTimeout()` value
- Optimize REST API call performance
- Consider async/polling pattern

## Next Steps

1. **Review the full example**: `CmpRaWithRestUpstream.java`
2. **Adapt to your CA's API**: Modify REST payload/response parsing
3. **Add security**: Implement proper credential loading
4. **Test thoroughly**: Start with unit tests, then integration tests
5. **Deploy**: Package as part of your application

## Resources

- [CMP RA Component Source Code](./cmp-ra-component/src/main/java/)
- [Lightweight CMP Profile](https://tools.ietf.org/wg/lamps/draft-ietf-lamps-lightweight-cmp-profile/)
- [BouncyCastle CMP Documentation](https://www.bouncycastle.org/)
