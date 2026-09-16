import com.siemens.pki.cmpracomponent.configuration.*;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Simple Example: How to Use the CMP RA Component
 * 
 * This example demonstrates how to instantiate and use the CMP RA (Registration Authority)
 * component to handle certificate enrollment requests from end entities (EEs) and forward
 * them to a Certificate Authority (CA).
 * 
 * The CMP RA component acts as an intermediary between EEs requesting certificates and
 * the CA that issues them. It supports all CMP operations defined in RFC 9483 (Lightweight
 * CMP Profile), including:
 * - ir (Initial Request)
 * - cr (Certification Request)
 * - p10cr (PKCS#10 Certification Request)
 * - kur (Key Update Request)
 * - rr (Revocation Request)
 * - Nested messages
 * - Delayed delivery with polling
 */
public class SimpleCmpRaExample {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(SimpleCmpRaExample.class);
    
    public static void main(String[] args) throws Exception {
        System.out.println("=== CMP RA Component Example ===\n");
        
        // Step 1: Create configuration for the RA component
        Configuration config = createRaConfiguration();
        
        // Step 2: Create upstream exchange interface (communicates with CA)
        UpstreamExchange upstreamExchange = createUpstreamExchange();
        
        // Step 3: Instantiate the CMP RA component
        CmpRaInterface raComponent = CmpRaComponent.instantiateCmpRaComponent(config, upstreamExchange);
        
        System.out.println("✓ CMP RA Component successfully instantiated!\n");
        
        // Step 4: Use the RA component to process CMP requests
        // In a real application, this would be called by your HTTP/CoAP server
        // when receiving requests from end entities
        
        System.out.println("The RA component is now ready to process CMP requests.");
        System.out.println("Call raComponent.processRequest(requestBytes) to process incoming CMP requests.\n");
        
        // Example of processing a request (pseudo-code):
        // byte[] cmpRequestFromEE = ... // received from network
        // byte[] cmpResponseToEE = raComponent.processRequest(cmpRequestFromEE);
        // sendResponseToEE(cmpResponseToEE);
        
        demonstrateUsage(raComponent);
    }
    
    /**
     * Creates a complete RA configuration.
     * 
     * The configuration defines:
     * - Downstream credentials (for communicating with EEs)
     * - Upstream credentials (for communicating with CA)
     * - Trust anchors for verification
     * - Message protection settings
     * - Optional inventory and persistency interfaces
     */
    private static Configuration createRaConfiguration() throws Exception {
        System.out.println("Step 1: Creating RA Configuration...");
        
        // For this example, we'll create a minimal configuration
        // In production, you would load these from files or a configuration system
        
        return new Configuration() {
            
            @Override
            public CkgContext getCkgConfiguration(String certProfile, int bodyType) {
                // Central Key Generation not used in this example
                return null;
            }
            
            @Override
            public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
                // Configure downstream interface (towards End Entities)
                return new CmpMessageInterface() {
                    @Override
                    public CredentialContext getOutputCredentials() {
                        // Credentials used to sign/protect outgoing messages to EEs
                        // For signature-based protection:
                        try {
                            return loadSignatureCredentials(
                                "ra-downstream-keystore.p12", 
                                "changeit"
                            );
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to load downstream credentials", e);
                        }
                    }
                    
                    @Override
                    public VerificationContext getInputVerification() {
                        // Trust anchors for verifying incoming messages from EEs
                        return loadTrustAnchors("ee-root-ca.pem");
                    }
                    
                    @Override
                    public CmpMessageInterface.ReprotectMode getReprotectMode() {
                        // How to handle message protection when forwarding
                        return CmpMessageInterface.ReprotectMode.reprotect;
                    }
                    
                    @Override
                    public boolean isMessageTimeDeviationAllowed(long deviation) {
                        // Allow messages within 5 minutes time deviation
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
                        return null; // No nested messages in this example
                    }
                };
            }
            
            @Override
            public int getDownstreamTimeout(String certProfile, int bodyType) {
                return 60; // 60 seconds timeout for downstream
            }
            
            @Override
            public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
                // Trust anchors for verifying enrolled certificates
                return loadTrustAnchors("enrollment-root-ca.pem");
            }
            
            @Override
            public boolean getForceRaVerifyOnUpstream(String certProfile, int bodyType) {
                // Set POPO to RaVerified for upstream messages
                return false;
            }
            
            @Override
            public InventoryInterface getInventory(String certProfile, int bodyType) {
                // Optional: Interface to external inventory system
                // Can be used to authorize/modify certificate requests
                return new InventoryInterface() {
                    @Override
                    public CheckAndModifyResult checkAndModifyCertRequest(
                            byte[] transactionID,
                            String requesterDn,
                            byte[] certTemplate,
                            String requestedSubjectDn,
                            byte[] pkiMessage) {
                        
                        LOGGER.info("Processing certificate request for: {}", requestedSubjectDn);
                        
                        // Here you could:
                        // 1. Check if the requester is authorized
                        // 2. Modify the certificate template
                        // 3. Log the request to an audit system
                        
                        return new CheckAndModifyResult() {
                            @Override
                            public boolean isGranted() {
                                return true; // Grant the request
                            }
                            
                            @Override
                            public byte[] getUpdatedCertTemplate() {
                                return null; // Don't modify the template
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
                        return true; // Accept PKCS#10 requests
                    }
                    
                    @Override
                    public boolean learnEnrollmentResult(
                            byte[] transactionID,
                            byte[] certificate,
                            String serialNumber,
                            String subjectDN,
                            String issuerDN) {
                        LOGGER.info("Certificate issued: {} (SN: {})", subjectDN, serialNumber);
                        return true;
                    }
                };
            }
            
            @Override
            public PersistencyInterface getPersistency() {
                // Optional: Persistency for delayed delivery support
                // Allows RA to survive restarts during long-running transactions
                return new DefaultPersistencyImplementation();
            }
            
            @Override
            public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
                return 30; // Poll every 30 seconds for delayed responses
            }
            
            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(
                    String certProfile, String infoTypeOid) {
                return null; // No custom support messages in this example
            }
            
            @Override
            public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
                // Configure upstream interface (towards CA)
                return new CmpMessageInterface() {
                    @Override
                    public CredentialContext getOutputCredentials() {
                        // Credentials used to sign/protect outgoing messages to CA
                        try {
                            return loadSignatureCredentials(
                                "ra-upstream-keystore.p12", 
                                "changeit"
                            );
                        } catch (Exception e) {
                            throw new RuntimeException("Failed to load upstream credentials", e);
                        }
                    }
                    
                    @Override
                    public VerificationContext getInputVerification() {
                        // Trust anchors for verifying incoming messages from CA
                        return loadTrustAnchors("ca-root-ca.pem");
                    }
                    
                    @Override
                    public CmpMessageInterface.ReprotectMode getReprotectMode() {
                        return CmpMessageInterface.ReprotectMode.reprotect;
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
            
            @Override
            public boolean isRaVerifiedAcceptable(String certProfile, int bodyType) {
                // Accept RaVerified POPO (Proof of Possession)
                return false; // Require signature-based POPO
            }
            
            // Helper methods (in real code, these would load actual files)
            private SignatureCredentialContext loadSignatureCredentials(String keystorePath, String password) {
                // Load PKCS#12 keystore with RA's private key and certificate chain
                // This is used to sign outgoing CMP messages
                System.out.println("  - Loading credentials from: " + keystorePath);
                return new SignatureCredentialContext() {
                    @Override
                    public java.security.PrivateKey getPrivateKey() {
                        // Return private key from keystore
                        return null; // Placeholder
                    }
                    
                    @Override
                    public java.security.cert.Certificate[] getCertificateChain() {
                        // Return certificate chain from keystore
                        return null; // Placeholder
                    }
                };
            }
            
            private VerificationContext loadTrustAnchors(String rootCaPath) {
                // Load trusted root CA certificates
                // Used to verify signatures on incoming CMP messages
                System.out.println("  - Loading trust anchors from: " + rootCaPath);
                return new VerificationContext() {
                    @Override
                    public List<X509Certificate> getTrustAnchors() {
                        // Return list of trusted root certificates
                        return Collections.emptyList(); // Placeholder
                    }
                    
                    @Override
                    public List<X509Certificate> getIntermediateCertificates() {
                        // Return intermediate certificates if needed
                        return Collections.emptyList(); // Placeholder
                    }
                    
                    @Override
                    public CrlUpdateRetrievalHandler getCrlUpdateRetrievalHandler() {
                        return null; // No CRL checking in this example
                    }
                    
                    @Override
                    public boolean isCheckRevocation() {
                        return false; // Disable revocation checking for simplicity
                    }
                };
            }
        };
    }
    
    /**
     * Creates the upstream exchange interface.
     * 
     * This interface is responsible for:
     * - Sending CMP requests to the CA
     * - Receiving CMP responses from the CA
     * - Supporting both synchronous and asynchronous communication
     */
    private static UpstreamExchange createUpstreamExchange() {
        System.out.println("Step 2: Creating Upstream Exchange Interface...");
        
        return (request, certProfile, bodyTypeOfFirstRequest) -> {
            System.out.println("  - Sending CMP request to CA (bodyType: " + bodyTypeOfFirstRequest + ")");
            
            // In a real implementation, you would:
            // 1. Send the request bytes to your CA via HTTP, CoAP, or other protocol
            // 2. Wait for the response
            // 3. Return the response bytes
            
            // Example using HTTP:
            // HttpURLConnection conn = (HttpURLConnection) caUrl.openConnection();
            // conn.setRequestMethod("POST");
            // conn.setDoOutput(true);
            // conn.getOutputStream().write(request);
            // byte[] response = conn.getInputStream().readAllBytes();
            // return response;
            
            // For asynchronous/delayed delivery:
            // - Return null if no immediate response (CA is processing)
            // - The RA will initiate polling on behalf of the EE
            // - When response arrives later, call raComponent.gotResponseAtUpstream(response)
            
            System.out.println("  - (In real implementation, send to CA and return response)");
            
            // Placeholder - return null to simulate delayed delivery
            // In reality, you'd return the actual CA response
            return null;
        };
    }
    
    /**
     * Demonstrates how to use the RA component to process requests.
     */
    private static void demonstrateUsage(CmpRaInterface raComponent) {
        System.out.println("Step 3: Using the RA Component...\n");
        
        System.out.println("The RA component provides two main methods:\n");
        
        System.out.println("1. processRequest(byte[] request)");
        System.out.println("   - Called when receiving a CMP request from an EE");
        System.out.println("   - Returns the CMP response to send back to the EE");
        System.out.println("   - May return a 'waiting' indication if using delayed delivery\n");
        
        System.out.println("2. gotResponseAtUpstream(byte[] response)");
        System.out.println("   - Called when receiving a delayed response from the CA");
        System.out.println("   - Only needed for asynchronous upstream communication\n");
        
        System.out.println("Example workflow:");
        System.out.println("  EE --> [CMP Request] --> Your Server");
        System.out.println("                          ↓");
        System.out.println("                    raComponent.processRequest(request)");
        System.out.println("                          ↓");
        System.out.println("                    UpstreamExchange.sendReceiveMessage()");
        System.out.println("                          ↓");
        System.out.println("  EE <-- [CMP Response] <-- Your Server\n");
        
        System.out.println("For delayed delivery:");
        System.out.println("  1. processRequest() returns 'waiting' indication");
        System.out.println("  2. EE sends poll requests");
        System.out.println("  3. CA responds asynchronously");
        System.out.println("  4. Call gotResponseAtUpstream(caResponse)");
        System.out.println("  5. Next poll returns the actual response\n");
    }
}
