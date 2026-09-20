# RFC 9483 Lightweight CMP Profile Gateway - Implementation Plan

## Project Overview
Implement an RFC 9483 compliant CMP-to-REST gateway that receives CMP messages from end entities and forwards REST API calls to the CEMA PKI system. The implementation leverages the siemens/cmp-ra-component library for all CMP message processing, certificate handling, and cryptographic operations.

## Architecture

### High-Level Design
```
End Entity (EE) ←[CMP over HTTP]→ CMP Gateway ←[REST/HTTPS]→ CEMA RA API
     ↓                                    ↓                        ↓
  RFC 9483 LCMP                    Uses cmp-ra-component     https://localhost:5443/cema/ccm/svc/db.file/rest/v2
  Messages                         for all CMP processing    /ca/{caName}/template/{tplName}/issue
  (ir, cr, p10cr,                                          /ca/auto-issue/{lookupName}
   kur, rr, poll)                                         /ca/{caName}/fetch
                                                          /ca/{caName}/revoke
```

### Component Architecture (using cmp-ra-component)
1. **Downstream Interface** (EE → Gateway): CMP server using `CmpRaComponent.instantiateCmpRaComponent()`
   - Implements `CmpRaComponent.CmpRaInterface`
   - Receives DER-encoded CMP messages via HTTP on port 9000
   - Uses `com.sun.net.httpserver.HttpServer` (same as cmp-ra-component examples)

2. **Upstream Interface** (Gateway → CEMA RA): REST client implementing `CmpRaComponent.UpstreamExchange`
   - Translates CMP requests to REST API calls
   - Handles synchronous (201) and asynchronous (202) responses
   - Manages CSRF tokens via `/auth/identify`
   - Supports client certificate and HTTP Basic authentication

3. **Configuration**: Implements `Configuration` interface
   - Static configuration for test CA (CA name, template name)
   - MAC-based protection for downstream (RFC 9483 compliant)
   - Signature-based protection for upstream (via REST credentials)
   - In-memory persistency (default `PersistencyInterface`)
   - No inventory validation (default accept-all)

## Core Functionality (RFC 9483 LCMP Core)

### Supported CMP Operations
1. **Initialization Request (IR)** - bodyType 0
   - First-time enrollment with new key pair
   - Maps to: POST `/ca/{caName}/template/{tplName}/issue` with generated CSR
   
2. **Certification Request (CR)** - bodyType 2
   - Renewal/update with existing certificate
   - Maps to: POST `/ca/{caName}/template/{tplName}/issue` with CSR

3. **PKCS#10 Certification Request (P10CR)** - bodyType 19
   - Legacy PKCS#10 based enrollment
   - Maps to: POST `/ca/auto-issue/{lookupName}` with PKCS#10 CSR

4. **Key Update Request (KUR)** - bodyType 7
   - Certificate renewal with new key
   - Maps to: POST `/ca/{caName}/template/{tplName}/issue` with new CSR

5. **Revocation Request (RR)** - bodyType 11
   - Certificate revocation
   - Maps to: PATCH `/ca/{caName}/revoke` with serial number

6. **Poll Request** - bodyType 3
   - For delayed delivery (async operations)
   - Maps to: POST `/ca/{caName}/fetch` with UUID

### Message Protection (RFC 9483 Compliance)
- **Downstream (EE → Gateway)**: MAC-based protection per RFC 9483 Section 5.2
  - Uses `SharedSecretCredentialContext` for outgoing messages
  - Uses `VerificationContext.getSharedSecret()` for incoming validation
  - Algorithm: HMAC-SHA256 (default in cmp-ra-component)
  
- **Upstream (Gateway → CEMA)**: REST authentication
  - Primary: Client certificate (PKCS#12)
  - Fallback: HTTP Basic authentication
  - CSRF token from `/auth/identify`

### Synchronous Communication Model
Per RFC 9483 and user requirements:
- EE ↔ Gateway: **Synchronous** - immediate CMP response required
- Gateway ↔ CEMA RA: **Flexible** - handles both sync (201) and async (202)
  - For async: Gateway polls CEMA on behalf of EE
  - Gateway returns CMP "waiting" indication if CEMA returns 202
  - Subsequent poll requests from EE trigger CEMA fetch

## Implementation Structure

```
lcmp-gateway/
├── build.gradle                 # Gradle build file
├── settings.gradle
├── src/main/java/com/example/lcmpgateway/
│   ├── Main.java                # Application entry point, HTTP server setup
│   ├── configuration/
│   │   ├── LcmpConfiguration.java           # Implements Configuration interface
│   │   ├── DownstreamCmpConfig.java         # Implements CmpMessageInterface for downstream
│   │   ├── UpstreamCmpConfig.java           # Implements CmpMessageInterface for upstream
│   │   ├── MacCredentialContext.java        # Implements SharedSecretCredentialContext
│   │   └── VerificationContextImpl.java     # Implements VerificationContext
│   ├── upstream/
│   │   ├── RestUpstreamExchange.java        # Implements UpstreamExchange
│   │   ├── RestClient.java                  # HTTP client for REST calls
│   │   ├── AuthHandler.java                 # Client cert + Basic auth + CSRF
│   │   └── MessageTranslator.java           # CMP ↔ REST JSON translation
│   ├── downstream/
│   │   └── CmpHttpHandler.java              # HttpHandler for CMP messages
│   ├── model/
│   │   ├── CertificateRequestMapper.java    # CRMF/CertTemplate → CertificateRequestSign
│   │   ├── RevocationMapper.java            # RR → RevocationRequest
│   │   └── ResponseParser.java              # REST JSON → CMP ip/cp/kup/rp
│   └── util/
│       ├── ErrorMapper.java                 # HTTP errors → CMP PKIFailureInfo
│       └── Logger.java                      # java.util.logging wrapper
└── src/test/java/com/example/lcmpgateway/
    └── IntegrationTest.java     # Basic integration tests
```

## Configuration Properties

Stored in `lcmp.properties` (loaded at startup):

```properties
# CEMA RA REST API
ra.rest.endpoint=https://localhost:5443/cema/ccm/svc/db.file/rest/v2
ra.ca.name=test-ca                    # Placeholder, configurable later
ra.template.name=default-template     # Placeholder, configurable later
ra.lookup.name=default-lookup         # For auto-issue endpoint

# REST Authentication
ra.auth.type=certificate              # "certificate" or "basic"
ra.auth.keystore.path=/path/to/client.p12
ra.auth.keystore.password=changeit
ra.auth.keystore.alias=client
ra.auth.basic.username=gateway-user
ra.auth.basic.password=gateway-password

# CMP Server (Downstream)
cmp.server.host=localhost
cmp.server.port=9000
cmp.mac.secret=shared-secret-key      # Base64-encoded shared secret for MAC
cmp.mac.senderKid=gateway-kid         # Optional KID for MAC

# Logging
logging.level=INFO                    # FINEST, FINER, FINE, INFO, WARNING, SEVERE
```

## Error Handling Strategy

### HTTP Status Code → CMP PKIFailureInfo Mapping (per RFC 9483 Section 6)

| HTTP Status | CMP Failure Info | PKIFailureInfo Constant |
|-------------|------------------|-------------------------|
| 400 Bad Request | badRequest | 0 |
| 401 Unauthorized | badAlg / badIdentity | 1 / 5 |
| 403 Forbidden | notAuthorized | 4 |
| 404 Not Found | recipientNotFound | 10 |
| 409 Conflict | alreadyRevoked / systemFailure | 23 / 2 |
| 500 Internal Server Error | systemFailure | 2 |
| 503 Service Unavailable | systemFailure | 2 |

### Implementation
- `ErrorMapper.java` converts REST exceptions to appropriate CMP error responses
- All errors logged with full details using `java.util.logging`
- CMP responses contain generic error info per RFC 9483 (no internal details exposed)

## Build System

### Gradle Configuration
- Java 17 (matching cmp-ra-component requirements)
- Dependencies:
  - `siemens:cmp-ra-component`
  - `org.bouncycastle:bcprov-jdk18on`
  - `org.bouncycastle:bcpkix-jdk18on`

## Key Implementation Details

### 1. CMP Message Processing Flow
```
EE sends CMP request (DER) 
  ↓
CmpHttpHandler receives via HTTP POST
  ↓
CmpRaInterface.processRequest() (provided by cmp-ra-component)
  ↓
[cmp-ra-component validates MAC, parses message]
  ↓
UpstreamExchange.sendReceiveMessage() (our implementation)
  ↓
RestUpstreamExchange translates CMP → REST JSON
  ↓
RestClient executes HTTP call to CEMA RA
  ↓
Response parsed: CMP response (DER) returned
  ↓
[cmp-ra-component adds MAC protection]
  ↓
CmpHttpHandler sends CMP response to EE
```

### 2. Asynchronous Handling (HTTP 202)
```
CEMA returns 202 + UUID
  ↓
Gateway stores UUID in memory (transaction ID → UUID mapping)
  ↓
Gateway returns CMP "waiting" indication with retryAfter
  ↓
EE sends CMP poll request
  ↓
Gateway calls POST /ca/{caName}/fetch with UUID
  ↓
If still pending: return 202 → CMP waiting
If ready: return 201 + cert → CMP ip/cp/kup
```

### 3. CSRF Token Management
```
On first REST call (or when token expired):
  POST /auth/identify → receive CSRF token
  Store token in RestClient
  Include in X-CSRF-Token header for all modifying operations
```

### 4. Certificate Template Mapping
For initial implementation, static configuration:
- All IR/CR/KUR → `{ra.ca.name}/{ra.template.name}/issue`
- All P10CR → `auto-issue/{ra.lookup.name}`
- Future: Extract from CMP certProfile or subject DN pattern

## RFC 9483 Compliance Checklist

### Implemented (Core)
- [x] IR, CR, P10CR, KUR, RR message types
- [x] Polling for delayed delivery
- [x] MAC-based protection (downstream)
- [x] Signature-based authentication (upstream via REST)
- [x] Error handling per Section 6
- [x] Synchronous EE communication
- [x] Transaction ID handling
- [x] CertTemplate extraction and mapping

### Deferred (Future Enhancement)
- [ ] Central Key Generation (CKG)
- [ ] GENM/GENP messages (CA certs, CRLs, etc.)
- [ ] Nested messages
- [ ] Multiple CA/template routing
- [ ] Persistent storage (database)
- [ ] Inventory integration
- [ ] OCSP/CRL distribution via CMP

## Testing Strategy

### Integration Tests
1. **Basic Enrollment Flow**
   - Send IR → Verify IP response with certificate
   - Send CR → Verify CP response
   - Send P10CR → Verify CP response

2. **Key Update Flow**
   - Send KUR → Verify KUP response

3. **Revocation Flow**
   - Send RR → Verify RP response

4. **Async Enrollment**
   - Send IR → Receive waiting indication
   - Send poll → Receive waiting
   - Send poll → Receive certificate

5. **Error Scenarios**
   - Invalid MAC → CMP error response
   - REST 403 → CMP notAuthorized
   - REST 404 → CMP recipientNotFound

### Test Tools
- Use Bouncy Castle CMP client for test requests
- Mock REST server for offline testing
- Real CEMA RA instance for integration validation

## Deployment

### Running the Gateway
```bash
# Set configuration
export LCMP_CONFIG=/path/to/lcmp.properties

# Start gateway
java -jar build/libs/lcmp-gateway.jar

# Gateway listens on http://localhost:9000/cmp
```

### End Entity Configuration
EEs configure CMP client to point to:
- URL: `http://gateway-host:9000/cmp`
- Protection: MAC with shared secret
- Sender KID: as configured in gateway

## Future Enhancements

### Easy Extension Points
1. **Multiple CA Support**: Modify `LcmpConfiguration.getCkgConfiguration()` to route based on certProfile
2. **Database Persistency**: Implement `PersistencyInterface` with JDBC
3. **Inventory Validation**: Implement `InventoryInterface` for policy checks
4. **Additional CMP Messages**: Add GENM handlers via `getSupportMessageHandler()`
5. **Dynamic Configuration**: Hot-reload properties file

### Potential Additions
- REST API for gateway management
- Metrics/monitoring endpoints
- Load balancing support (with shared persistency)
- Mutual TLS for downstream interface
- Certificate profile-based routing

## References
- RFC 9483: Lightweight Certificate Management Protocol (CMP) Profile
- RFC 9480: Certificate Management Protocol (CMP) Updates
- RFC 9481: Certificate Management Protocol (CMP) Algorithms
- siemens/cmp-ra-component README and Javadoc
- CEMA RA OpenAPI Specification (openapi.json)