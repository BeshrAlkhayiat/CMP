/*
 * Complete Example: CMP RA Component with REST API Upstream
 * 
 * This example demonstrates how to:
 * 1. Accept CMP requests from end entities (hosts)
 * 2. Convert CMP requests to REST API calls to your CA
 * 3. Convert REST API responses back to CMP responses
 * 
 * Architecture:
 * [End Entity] --CMP--> [Your RA Application] --REST API--> [CA System]
 */

import com.siemens.pki.cmpracomponent.configuration.*;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x509.Certificate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.function.BiFunction;

/**
 * MAIN EXAMPLE: Complete RA implementation with REST API upstream
 */
public class CmpRaWithRestUpstream {

    public static void main(String[] args) throws Exception {
        System.out.println("=== CMP RA Component with REST API Upstream ===\n");

        // Step 1: Create configuration
        Configuration config = new RestApiConfiguration();

        // Step 2: Create upstream exchange that converts CMP to REST
        UpstreamExchange restUpstream = new RestApiUpstreamExchange(
            "https://ca.example.com/api/v1/certificates",
            "api-key-here"
        );

        // Step 3: Instantiate the RA component
        CmpRaInterface raComponent = CmpRaComponent.instantiateCmpRaComponent(config, restUpstream);

        System.out.println("RA Component instantiated successfully!");
        System.out.println("Ready to process CMP requests from end entities.\n");

        // Step 4: Example usage - simulate receiving a CMP request from a host
        // In real scenario, this comes from your HTTP server or message queue
        byte[] cmpRequestFromHost = loadSampleCmpRequest();
        
        try {
            // Process the CMP request
            byte[] cmpResponse = raComponent.processRequest(cmpRequestFromHost);
            
            // Send response back to the host
            sendResponseToHost(cmpResponse);
            
            System.out.println("Successfully processed CMP request and sent response!");
        } catch (Exception e) {
            System.err.println("Error processing request: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * CONFIGURATION IMPLEMENTATION
     * Defines all configuration needed by the RA component
     */
    static class RestApiConfiguration implements Configuration {

        @Override
        public CkgContext getCkgConfiguration(String certProfile, int bodyType) {
            // We're not doing central key generation in this example
            return null;
        }

        @Override
        public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
            // Configure downstream (towards end entities)
            // This defines how we protect messages TO the end entities
            return new CmpMessageInterface() {
                @Override
                public ProtectionMode getProtectionMode() {
                    // Use signature-based protection for downstream
                    return ProtectionMode.SIGNATURE;
                }

                @Override
                public KeyStore getCredentialStore() {
                    // Load your RA's signing certificate and private key
                    // This is used to sign responses to end entities
                    return loadRaCredentialStore();
                }

                @Override
                public String getRecipientName() {
                    return "ra-downstream";
                }
            };
        }

        @Override
        public int getDownstreamTimeout(String certProfile, int bodyType) {
            // Timeout for downstream transactions (30 seconds)
            return 30;
        }

        @Override
        public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
            // Trust anchors for verifying certificates issued by CA
            return new VerificationContext() {
                @Override
                public KeyStore getTrustAnchorStore() {
                    return loadCaTrustAnchors();
                }

                @Override
                public KeyStore getCertificationPathStore() {
                    // Intermediate certificates if any
                    return loadIntermediateCerts();
                }
            };
        }

        @Override
        public boolean getForceRaVerifiedOnUpstream(String certProfile, int bodyType) {
            // Don't force RaVerified since we're not sending CMP upstream
            return false;
        }

        @Override
        public InventoryInterface getInventory(String certProfile, int bodyType) {
            // Optional: Add inventory/authorization logic here
            // For now, return null (no inventory check)
            return null;
        }

        @Override
        public PersistencyInterface getPersistency() {
            // Optional: Add persistence for delayed delivery
            // Return default empty implementation for now
            return Configuration.super.getPersistency();
        }

        @Override
        public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
            // If using polling, tell clients to retry after 5 seconds
            return 5;
        }

        @Override
        public SupportMessageHandlerInterface getSupportMessageHandler(String certProfile, String infoTypeOid) {
            // Handle general messages (GENM) if needed
            return null;
        }

        @Override
        public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
            // We're NOT using CMP upstream, so return null
            // The REST API exchange handles upstream communication
            return null;
        }

        @Override
        public boolean isRaVerifiedAcceptable(String certProfile, int bodyType) {
            // Don't accept RaVerified from end entities (require signature)
            return false;
        }
    }

    /**
     * UPSTREAM EXCHANGE IMPLEMENTATION
     * Converts CMP requests to REST API calls and back
     */
    static class RestApiUpstreamExchange implements UpstreamExchange {
        
        private final String caRestApiUrl;
        private final String apiKey;
        private final HttpClient httpClient;

        public RestApiUpstreamExchange(String caRestApiUrl, String apiKey) {
            this.caRestApiUrl = caRestApiUrl;
            this.apiKey = apiKey;
            this.httpClient = HttpClient.newHttpClient();
        }

        @Override
        public byte[] sendReceiveMessage(byte[] cmpRequest, String certProfile, int bodyType) throws Exception {
            System.out.println("Converting CMP request to REST API call...");
            System.out.println("  Body Type: " + bodyType + " (2=CR, 0=IR, 7=KUR)");
            System.out.println("  Cert Profile: " + (certProfile != null ? certProfile : "none"));

            // Step 1: Parse the CMP request to extract relevant data
            CmpRequestData requestData = parseCmpRequest(cmpRequest);

            // Step 2: Convert to REST API payload
            String restPayload = buildRestApiPayload(requestData, certProfile);

            // Step 3: Call the CA REST API
            String restResponse = callCaRestApi(restPayload);

            // Step 4: Convert REST response back to CMP response
            byte[] cmpResponse = buildCmpResponse(restResponse, cmpRequest, bodyType);

            System.out.println("Successfully converted REST response to CMP response");
            return cmpResponse;
        }

        /**
         * Parse CMP request to extract certificate request data
         */
        private CmpRequestData parseCmpRequest(byte[] cmpRequestBytes) throws IOException {
            ASN1InputStream ais = new ASN1InputStream(cmpRequestBytes);
            PKIMessage pkiMsg = PKIMessage.getInstance(ais.readObject());
            
            // Extract sender information
            String sender = pkiMsg.getHeader().getSender().toString();
            
            // Extract the certification request (for CR/IR/KUR)
            // This is simplified - you'd extract the actual CSR based on bodyType
            byte[] csrBytes = extractCsrFromPkiMessage(pkiMsg);
            
            return new CmpRequestData(sender, csrBytes, bodyType);
        }

        private byte[] extractCsrFromPkiMessage(PKIMessage pkiMsg) {
            // Simplified extraction - in production you'd properly extract
            // the CertReqMsg or P10CR content based on the body type
            try {
                return pkiMsg.getBody().toASN1Primitive().getEncoded();
            } catch (IOException e) {
                throw new RuntimeException("Failed to extract CSR", e);
            }
        }

        /**
         * Build REST API JSON payload from CMP request data
         */
        private String buildRestApiPayload(CmpRequestData requestData, String certProfile) {
            // Build JSON payload for your CA's REST API
            // Adjust this based on your actual CA's API format
            
            String base64Csr = Base64.getEncoder().encodeToString(requestData.csrBytes);
            
            StringBuilder json = new StringBuilder();
            json.append("{");
            json.append("\"csr\": \"").append(base64Csr).append("\",");
            json.append("\"profile\": \"").append(certProfile != null ? certProfile : "default").append("\",");
            json.append("\"requester\": \"").append(requestData.sender).append("\"");
            json.append("}");
            
            return json.toString();
        }

        /**
         * Call the CA's REST API
         */
        private String callCaRestApi(String payload) throws Exception {
            System.out.println("Calling CA REST API at: " + caRestApiUrl);
            
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(caRestApiUrl))
                .header("Content-Type", "application/json")
                .header("Authorization", "Bearer " + apiKey)
                .POST(HttpRequest.BodyPublishers.ofString(payload))
                .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new Exception("CA REST API returned error: " + response.statusCode() + " - " + response.body());
            }

            System.out.println("CA REST API responded successfully");
            return response.body();
        }

        /**
         * Convert REST API response to CMP response
         */
        private byte[] buildCmpResponse(String restResponse, byte[] originalRequest, int bodyType) throws Exception {
            // Parse the REST API response
            // This is simplified - adjust based on your actual CA's response format
            
            // Example REST response: {"certificate": "MIID...", "status": "issued"}
            // You need to extract the certificate and build a proper CMP IP/CP/KUP response
            
            // For this example, we'll create a minimal successful CMP response
            // In production, you'd use BouncyCastle CMP classes to build proper responses
            
            System.out.println("Building CMP response from REST API result");
            
            // This is where you'd construct the proper CMP response PKIMessage
            // containing the issued certificate (IP), certification response (CP), etc.
            // For brevity, returning a placeholder - see helper methods below
            
            return buildSuccessfulCmpResponse(originalRequest, restResponse, bodyType);
        }

        private byte[] buildSuccessfulCmpResponse(byte[] originalRequest, String restResponse, int bodyType) 
                throws Exception {
            // In production, use BouncyCastle to build proper CMP response:
            // 1. Parse the REST response to get the certificate
            // 2. Create PKIHeaderBuilder with matching transaction ID
            // 3. Create appropriate body (ip, cp, kup) with the certificate
            // 4. Sign the response using downstream credentials
            // 5. Encode to DER
            
            // Placeholder implementation - replace with actual CMP response building
            System.out.println("  Building CMP " + getBodyTypeName(bodyType) + " response");
            
            // For a real implementation, see the BouncyCastle CMP examples
            // or the Lightweight CMP RA reference implementation
            throw new UnsupportedOperationException(
                "Full CMP response building requires BouncyCastle CMP classes. " +
                "See documentation for complete implementation."
            );
        }

        private String getBodyTypeName(int bodyType) {
            switch (bodyType) {
                case 0: return "IR/IP";
                case 2: return "CR/CP";
                case 7: return "KUR/KUP";
                case 11: return "RR";
                default: return "type-" + bodyType;
            }
        }
    }

    // Helper data class
    static class CmpRequestData {
        final String sender;
        final byte[] csrBytes;
        final int bodyType;

        CmpRequestData(String sender, byte[] csrBytes, int bodyType) {
            this.sender = sender;
            this.csrBytes = csrBytes;
            this.bodyType = bodyType;
        }
    }

    // ========================================================================
    // HELPER METHODS - Replace these with your actual implementations
    // ========================================================================

    private static byte[] loadSampleCmpRequest() {
        // In production, this comes from your HTTP endpoint or message queue
        // For demo, return a placeholder
        System.out.println("Loading sample CMP request (placeholder)...");
        return new byte[]{0x30, 0x00}; // Invalid ASN.1 - just a placeholder
    }

    private static void sendResponseToHost(byte[] response) {
        // In production, send this back via HTTP/MQTT/etc. to the end entity
        System.out.println("Sending CMP response to host (" + response.length + " bytes)");
    }

    private static KeyStore loadRaCredentialStore() {
        // Load your RA's certificate and private key for signing downstream messages
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            // ks.load(new FileInputStream("ra-credential.p12"), "password".toCharArray());
            return ks;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RA credentials", e);
        }
    }

    private static KeyStore loadCaTrustAnchors() {
        // Load CA root certificates for verification
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            // ks.load(new FileInputStream("ca-trust.jks"), "password".toCharArray());
            return ks;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load CA trust anchors", e);
        }
    }

    private static KeyStore loadIntermediateCerts() {
        // Load intermediate certificates if needed
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            // ks.load(new FileInputStream("intermediates.jks"), "password".toCharArray());
            return ks;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load intermediate certs", e);
        }
    }
}
