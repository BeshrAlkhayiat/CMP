# Complete Guide to Using the CMP RA Component

## Overview

The **CMP RA (Certificate Management Protocol Registration Authority) Component** is a Java library that helps you build applications that act as intermediaries between end entities (EEs) requesting certificates and Certificate Authorities (CAs) that issue them.

### What is an RA?

An RA sits between certificate requesters and the CA:
- **End Entities (EEs)** → Request certificates
- **Registration Authority (RA)** → Validates, authorizes, and forwards requests
- **Certificate Authority (CA)** → Issues certificates

### Key Features

The CMP RA component supports:
- ✅ All CMP operations from RFC 9483 (Lightweight CMP Profile)
- ✅ Signature-based and password-based (MAC) message protection
- ✅ Synchronous and asynchronous communication
- ✅ Delayed delivery with polling support
- ✅ PKCS#10 request support for legacy systems
- ✅ Central Key Generation (CKG)
- ✅ Integration with external inventory systems
- ✅ Persistent state for long-running transactions
- ✅ Flexible configuration per certificate profile

---

## Architecture

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────┐
│ End Entity  │◄───────►│   CMP RA         │◄───────►│    CA       │
│ (EE)        │  Down-  │   Component      │  Up-    │ (Certificate│
│             │  stream │                  │  stream │  Authority) │
└─────────────┘         └──────────────────┘         └─────────────┘
```

### Message Flow

1. **Downstream** (EE → RA): EE sends CMP request to RA
2. **Processing**: RA validates, optionally modifies, and authorizes request
3. **Upstream** (RA → CA): RA forwards request to CA
4. **Response**: CA responds, RA processes and forwards back to EE

---

## Quick Start Example

Here's a minimal example of instantiating and using the CMP RA component:

```java
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;

public class MyRaApplication {
    
    public static void main(String[] args) throws Exception {
        // Step 1: Create configuration
        Configuration config = createConfiguration();
        
        // Step 2: Create upstream interface (to communicate with CA)
        UpstreamExchange upstreamExchange = createUpstreamExchange();
        
        // Step 3: Instantiate the RA component
        CmpRaInterface raComponent = CmpRaComponent.instantiateCmpRaComponent(
            config, 
            upstreamExchange
        );
        
        System.out.println("RA Component is ready!");
        
        // Step 4: Use in your server
        // byte[] response = raComponent.processRequest(requestBytes);
    }
    
    private static Configuration createConfiguration() {
        return new Configuration() {
            // Implement all configuration methods
            // See detailed example below
        };
    }
    
    private static UpstreamExchange createUpstreamExchange() {
        return (request, certProfile, bodyType) -> {
            // Send request to CA and return response
            // Implementation depends on your CA's interface
        };
    }
}
```

---

## Detailed Configuration Guide

### Configuration Interface

The `Configuration` interface is the heart of the RA component. It defines how the RA behaves for different scenarios. Most methods accept:
- `certProfile`: Certificate profile identifier (can be null)
- `bodyType`: CMP message type (ir=0, cr=2, p10cr=4, kur=7, rr=11, etc.)

This allows **dynamic, profile-specific behavior**.

### Required Configuration Methods

#### 1. Downstream Configuration (towards EEs)

```java
@Override
public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
    return new CmpMessageInterface() {
        
        @Override
        public CredentialContext getOutputCredentials() {
            // Return credentials for signing outgoing messages to EEs
            return new SignatureCredentialContext(privateKey, certChain);
        }
        
        @Override
        public VerificationContext getInputVerification() {
            // Return trust anchors for verifying incoming messages from EEs
            return new VerificationContext(trustAnchors, intermediateCerts);
        }
        
        @Override
        public ReprotectMode getReprotectMode() {
            // How to handle message protection
            return ReprotectMode.reprotect; // Re-sign messages
        }
        
        @Override
        public boolean isMessageTimeDeviationAllowed(long deviation) {
            // Allow messages within 5 minutes
            return Math.abs(deviation) < 300000;
        }
        
        @Override
        public boolean isCacheExtraCerts() {
            return false;
        }
        
        @Override
        public boolean getSuppressRedundantExtraCerts() {
            return false;
        }
        
        @Override
        public NestedEndpointContext getNestedEndpointContext() {
            return null; // Or configure for nested messages
        }
    };
}

@Override
public int getDownstreamTimeout(String certProfile, int bodyType) {
    return 60; // 60 seconds timeout
}
```

#### 2. Upstream Configuration (towards CA)

```java
@Override
public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
    return new CmpMessageInterface() {
        
        @Override
        public CredentialContext getOutputCredentials() {
            // Credentials for signing messages to CA
            return new SignatureCredentialContext(raPrivateKey, raCertChain);
        }
        
        @Override
        public VerificationContext getInputVerification() {
            // Trust anchors for verifying CA responses
            return new VerificationContext(caRootCerts, caIntermediateCerts);
        }
        
        @Override
        public ReprotectMode getReprotectMode() {
            return ReprotectMode.reprotect;
        }
        
        @Override
        public boolean isMessageTimeDeviationAllowed(long deviation) {
            return Math.abs(deviation) < 300000;
        }
        
        @Override
        public boolean isCacheExtraCerts() {
            return false;
        }
        
        @Override
        public boolean getSuppressRedundantExtraCerts() {
            return false;
        }
        
        @Override
        public NestedEndpointContext getNestedEndpointContext() {
            return null;
        }
    };
}
```

#### 3. Enrollment Trust

```java
@Override
public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
    // Trust anchors for verifying the issued certificate
    return new VerificationContext(enrollmentRootCerts, null);
}
```

#### 4. Inventory Interface (Optional but Recommended)

The inventory interface allows you to authorize and modify certificate requests:

```java
@Override
public InventoryInterface getInventory(String certProfile, int bodyType) {
    return new InventoryInterface() {
        
        @Override
        public CheckAndModifyResult checkAndModifyCertRequest(
                byte[] transactionID,
                String requesterDn,
                byte[] certTemplate,
                String requestedSubjectDn,
                byte[] pkiMessage) {
            
            // Log the request
            logger.info("Certificate request from: {}", requesterDn);
            
            // Check against your inventory/database
            boolean authorized = checkAuthorization(requestedSubjectDn);
            
            if (!authorized) {
                return new CheckAndModifyResult() {
                    @Override
                    public boolean isGranted() {
                        return false; // Deny the request
                    }
                    
                    @Override
                    public byte[] getUpdatedCertTemplate() {
                        return null;
                    }
                };
            }
            
            // Optionally modify the certificate template
            byte[] modifiedTemplate = modifyTemplate(certTemplate);
            
            return new CheckAndModifyResult() {
                @Override
                public boolean isGranted() {
                    return true; // Grant the request
                }
                
                @Override
                public byte[] getUpdatedCertTemplate() {
                    return modifiedTemplate;
                }
            };
        }
        
        @Override
        public boolean checkP10CertRequest(
                byte[] transactionID,
                String requesterDn,
                byte[] pkcs10CertRequest,
                String requestedSubjectDn,
                byte[] pkiMessage) {
            // Similar logic for PKCS#10 requests
            return checkAuthorization(requestedSubjectDn);
        }
        
        @Override
        public boolean learnEnrollmentResult(
                byte[] transactionID,
                byte[] certificate,
                String serialNumber,
                String subjectDN,
                String issuerDN) {
            // Called when certificate is successfully issued
            logger.info("Certificate issued: {} (SN: {})", subjectDN, serialNumber);
            updateInventory(subjectDN, serialNumber, certificate);
            return true;
        }
    };
}
```

#### 5. Persistency Interface (For Delayed Delivery)

```java
@Override
public PersistencyInterface getPersistency() {
    // Optional: Implement persistent storage for long-running transactions
    // This allows the RA to survive restarts during delayed delivery
    
    return new PersistencyInterface() {
        @Override
        public Map<String, byte[]> loadState() {
            // Load pending transactions from database
            return database.loadPendingTransactions();
        }
        
        @Override
        public void saveState(Map<String, byte[]> state) {
            // Save pending transactions to database
            database.savePendingTransactions(state);
        }
    };
}

// Or use the default implementation:
@Override
public PersistencyInterface getPersistency() {
    return new DefaultPersistencyImplementation();
}
```

#### 6. Other Configuration Methods

```java
@Override
public CkgContext getCkgConfiguration(String certProfile, int bodyType) {
    // Central Key Generation configuration (optional)
    return null; // Not using CKG
}

@Override
public boolean getForceRaVerifyOnUpstream(String certProfile, int bodyType) {
    // Set POPO to RaVerified for upstream messages
    return false;
}

@Override
public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
    // Polling interval for delayed delivery
    return 30; // 30 seconds
}

@Override
public SupportMessageHandlerInterface getSupportMessageHandler(
        String certProfile, String infoTypeOid) {
    // Handle custom GENM (General Message) types
    return null;
}

@Override
public boolean isRaVerifiedAcceptable(String certProfile, int bodyType) {
    // Accept RaVerified POPO from EEs?
    return false; // Require signature-based POPO
}
```

---

## Upstream Exchange Interface

The `UpstreamExchange` interface connects your RA to the CA:

```java
UpstreamExchange upstreamExchange = (request, certProfile, bodyTypeOfFirstRequest) -> {
    // 1. Send the CMP request to your CA
    // 2. Wait for response
    // 3. Return the response bytes
    
    // Example with HTTP:
    URL caUrl = new URL("https://ca.example.com/cmp");
    HttpURLConnection conn = (HttpURLConnection) caUrl.openConnection();
    conn.setRequestMethod("POST");
    conn.setDoOutput(true);
    conn.setRequestProperty("Content-Type", "application/pkixcmp");
    
    try (OutputStream os = conn.getOutputStream()) {
        os.write(request);
    }
    
    int status = conn.getResponseCode();
    if (status == 200) {
        return conn.getInputStream().readAllBytes();
    } else {
        throw new Exception("CA returned error: " + status);
    }
};
```

### Asynchronous/Delayed Delivery

If your CA doesn't respond immediately:

```java
UpstreamExchange upstreamExchange = (request, certProfile, bodyTypeOfFirstRequest) -> {
    // Send request asynchronously
    CompletableFuture<byte[]> future = sendToCaAsync(request);
    
    // Try to get response with short timeout
    try {
        return future.get(5, TimeUnit.SECONDS);
    } catch (TimeoutException e) {
        // No response yet - return null to trigger polling
        // Store the future to retrieve response later
        pendingRequests.put(transactionId, future);
        return null;
    }
};

// Later, when response arrives:
future.thenAccept(response -> {
    raComponent.gotResponseAtUpstream(response);
});
```

---

## Using the RA Component

Once instantiated, use the RA component in your server:

### Basic Usage

```java
// In your HTTP/CoAP server handler
public byte[] handleCmpRequest(byte[] requestBytes) throws Exception {
    // Process the CMP request
    byte[] responseBytes = raComponent.processRequest(requestBytes);
    return responseBytes;
}
```

### With Delayed Delivery

```java
public byte[] handleCmpRequest(byte[] requestBytes) throws Exception {
    byte[] response = raComponent.processRequest(requestBytes);
    
    // Check if it's a waiting indication
    PKIMessage responseMsg = PKIMessage.getInstance(response);
    if (responseMsg.getBody().getType() == PKIBody.TYPE_ERROR) {
        ErrorMsgContent error = ErrorMsgContent.getInstance(responseMsg.getBody().getContent());
        if (error.getPKIStatus() == PKIStatus.WAITING) {
            // Tell client to poll
            return response;
        }
    }
    
    return response;
}

// When CA responds asynchronously:
public void handleCaResponse(byte[] caResponse) throws Exception {
    raComponent.gotResponseAtUpstream(caResponse);
}
```

---

## Alternative: PKCS#10/X.509 Mode

For legacy systems using PKCS#10 instead of full CMP:

```java
BiFunction<byte[], String, byte[]> upstreamP10X509Exchange = (pkcs10Request, certProfile) -> {
    // Send PKCS#10 CSR to CA
    // Return X.509 certificate response
    return caService.issueCertificate(pkcs10Request);
};

Function<byte[], byte[]> raComponent = CmpRaComponent.instantiateP10X509CmpRaComponent(
    config, 
    upstreamP10X509Exchange
);

// Usage
byte[] cmpResponse = raComponent.apply(cmpP10crRequest);
```

---

## Complete Working Example

See the file `SimpleCmpRaExample.java` in this directory for a complete, commented example showing:
- Full configuration setup
- Upstream exchange implementation
- Inventory integration
- Best practices

---

## Common Use Cases

### 1. Simple Pass-Through RA

```java
Configuration config = new Configuration() {
    @Override
    public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
        return createSimpleInterface(eeCredentials, eeTrust);
    }
    
    @Override
    public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
        return createSimpleInterface(caCredentials, caTrust);
    }
    
    // ... other methods with defaults
};
```

### 2. RA with Authorization

```java
@Override
public InventoryInterface getInventory(String certProfile, int bodyType) {
    return new InventoryInterface() {
        @Override
        public CheckAndModifyResult checkAndModifyCertRequest(...) {
            // Check against LDAP/database
            if (!inventory.isAuthorized(requestedSubjectDn)) {
                return deniedResult();
            }
            return grantedResult();
        }
    };
}
```

### 3. Multi-Profile RA

```java
@Override
public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
    if ("profile-a".equals(certProfile)) {
        return profileAConfig;
    } else if ("profile-b".equals(certProfile)) {
        return profileBConfig;
    }
    return defaultConfig;
}
```

### 4. RA with Persistence

```java
@Override
public PersistencyInterface getPersistency() {
    return new DatabasePersistency(databaseConnection);
}
```

---

## Message Protection Options

### Signature-Based Protection

```java
CredentialContext credentials = new SignatureCredentialContext(privateKey, certChain);
```

### Password-Based MAC Protection

```java
CredentialContext credentials = new SharedSecret("password", salt);
```

### PBMAC1 Protection

```java
CredentialContext credentials = new SharedSecret("PBMAC1", password);
```

---

## Testing Your RA

Use the test framework provided in the component:

```java
@Test
public void testCertificateEnrollment() throws Exception {
    Configuration config = buildSignatureBasedDownstreamConfiguration();
    Function<PKIMessage, PKIMessage> client = launchCmpCaAndRa(config);
    
    // Create enrollment request
    PKIMessage request = createEnrollmentRequest();
    
    // Process through RA
    PKIMessage response = client.apply(request);
    
    // Verify response contains certificate
    CertRepMessage certRep = CertRepMessage.getInstance(response.getBody().getContent());
    assertNotNull(certRep.getCertRepContent().getCertResponse(0).getCertifiedKeyPair());
}
```

---

## Deployment Considerations

### 1. Security

- Protect private keys in HSM or secure keystore
- Use strong passwords/passphrases
- Enable certificate revocation checking
- Implement proper access controls

### 2. Performance

- Configure appropriate timeouts
- Use connection pooling for CA communication
- Consider caching for frequently accessed data
- Monitor transaction queues

### 3. High Availability

- Implement persistency for delayed delivery
- Use load balancing for multiple RA instances
- Configure proper failover mechanisms

### 4. Monitoring

- Enable SLF4J logging
- Monitor transaction success rates
- Track pending delayed deliveries
- Alert on error conditions

---

## Troubleshooting

### Common Issues

1. **"Invalid credentials" error**
   - Check keystore path and password
   - Verify certificate chain is complete

2. **"Verification failed" error**
   - Ensure trust anchors are correctly configured
   - Check certificate validity periods
   - Verify CRL/OCSP accessibility

3. **"Timeout" errors**
   - Increase timeout values
   - Check network connectivity
   - Verify CA availability

4. **Delayed delivery not working**
   - Implement persistency interface
   - Ensure polling is configured correctly
   - Check retry-after timing

---

## Additional Resources

- [RFC 9483 - Lightweight CMP Profile](https://datatracker.ietf.org/doc/rfc9483/)
- [RFC 9480 - CMP Updates](https://datatracker.ietf.org/doc/rfc9480/)
- [Bouncy Castle Library](https://www.bouncycastle.org/)
- [Lightweight CMP RA Application](https://github.com/siemens/LightweightCmpRa/)

---

## License

Apache License 2.0 - See LICENSE.txt for details.
