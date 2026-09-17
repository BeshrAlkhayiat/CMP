import com.siemens.pki.cmpracomponent.configuration.*;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;

/**
 * PoC: EJBCA CMP Bridge
 * 
 * ARCHITECTURE (Mode A - Pass Through):
 * [OpenSSL CMP] --(CMP Bytes)--> [Local HTTP Server] --(CMP Bytes)--> [EJBCA REST/CMP Endpoint]
 * 
 * This implementation uses the Siemens CMP RA Component to handle the heavy lifting
 * of CMP message parsing/validation, while simply forwarding the payload to EJBCA.
 * 
 * CONFIGURATION MAPPING (from CABackendParams-Kind-CMP.txt):
 * - CMP.EndpointAddress -> EJBCA_URL
 * - AuthenticationSharedSecret -> SHARED_SECRET
 * - CMP.HashAlgorithm -> SHA256 (Recommended over default SHA1)
 * - CMP.Dialect -> EJBCA
 * - CMP.ImplicitConfirm -> false
 */
public class EjbcaCmpBridge {

    private final String ejbcaUrl;
    private final String sharedSecret;
    private final String senderKid;
    private final CmpRaInterface raComponent;
    private final HttpClient httpClient;

    public EjbcaCmpBridge(String ejbcaUrl, String sharedSecret, String senderKid) throws Exception {
        this.ejbcaUrl = ejbcaUrl;
        this.sharedSecret = sharedSecret;
        this.senderKid = senderKid;
        this.httpClient = HttpClient.newHttpClient();

        // 1. Configure the RA Component for EJBCA
        Configuration config = new SimpleConfiguration(sharedSecret, senderKid);

        // 2. Implement the Upstream Exchange (The bridge to EJBCA)
        UpstreamExchange upstream = new UpstreamExchange() {
            @Override
            public byte[] sendReceiveMessage(byte[] cmpRequest, String certProfile, int bodyType) throws Exception {
                System.out.println("[UPSTREAM] Forwarding request to EJBCA: " + ejbcaUrl);
                
                HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(ejbcaUrl))
                    .header("Content-Type", "application/pkixcmp")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(cmpRequest))
                    .build();

                HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());

                if (response.statusCode() != 200) {
                    throw new IOException("EJBCA returned error code: " + response.statusCode());
                }

                System.out.println("[UPSTREAM] Received response from EJBCA (" + response.body().length + " bytes)");
                return response.body();
            }
        };

        // 3. Instantiate the RA Component
        this.raComponent = CmpRaComponent.instantiateCmpRaComponent(config, upstream);
        
        System.out.println("RA Component initialized successfully for EJBCA.");
    }

    /**
     * Starts the local HTTP server that OpenSSL will talk to.
     * Listens on localhost:8080 by default.
     */
    public void startServer(int port) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        
        server.createContext("/cmp", exchange -> {
            System.out.println("\n[DOWNSTREAM] Received request from OpenSSL on port " + port);
            
            try (InputStream is = exchange.getRequestBody()) {
                byte[] requestBytes = is.readAllBytes();
                System.out.println("[DOWNSTREAM] Read " + requestBytes.length + " bytes from client.");

                // Process using the RA Component (validates & forwards)
                byte[] responseBytes = raComponent.processRequest(requestBytes);

                exchange.getResponseHeaders().set("Content-Type", "application/pkixcmp");
                exchange.sendResponseHeaders(200, responseBytes.length);
                
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(responseBytes);
                    System.out.println("[DOWNSTREAM] Sent " + responseBytes.length + " bytes back to client.");
                }
            } catch (Exception e) {
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1);
            }
        });

        server.setExecutor(null); 
        server.start();
        System.out.println("============================================");
        System.out.println("EJBCA CMP Bridge Started!");
        System.out.println("Listening on: http://localhost:" + port + "/cmp");
        System.out.println("Forwarding to: " + ejbcaUrl);
        System.out.println("============================================");
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.out.println("Usage: java EjbcaCmpBridge <EJBCA_URL> <SHARED_SECRET> [SENDER_KID]");
            System.out.println("Example: java EjbcaCmpBridge https://ejbca.test/ejbca/publicweb/cmp/myprofile mySecretPassword myKeyId");
            System.exit(1);
        }

        String url = args[0];
        String secret = args[1];
        String kid = (args.length > 2) ? args[2] : null;

        try {
            EjbcaCmpBridge bridge = new EjbcaCmpBridge(url, secret, kid);
            bridge.startServer(8080);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Simple Configuration Implementation for EJBCA with Shared Secret
     * Maps settings from CABackendParams-Kind-CMP.txt to the Configuration interface
     */
    static class SimpleConfiguration implements Configuration {
        private final byte[] sharedSecret;
        private final String senderKid;

        public SimpleConfiguration(String secret, String kid) {
            this.sharedSecret = secret.getBytes();
            this.senderKid = kid;
        }

        @Override
        public CkgContext getCkgConfiguration(String certProfile, int bodyType) {
            return null; // No central key generation
        }

        @Override
        public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
            return new CmpMessageInterface() {
                @Override
                public ProtectionMode getProtectionMode() {
                    // Use MAC (shared secret) for downstream
                    return ProtectionMode.MAC;
                }

                @Override
                public byte[] getSecret() {
                    return sharedSecret;
                }

                @Override
                public String getSenderKID() {
                    return senderKid;
                }

                @Override
                public java.security.cert.X509Certificate getSenderCertificate() {
                    return null; // Not using signature-based protection
                }

                @Override
                public java.security.PrivateKey getSenderPrivateKey() {
                    return null; // Not using signature-based protection
                }

                @Override
                public java.util.List<java.security.cert.X509Certificate> getExtraCertificates() {
                    return Collections.emptyList();
                }

                @Override
                public boolean getImplicitConfirm() {
                    return false; // EJBCA typically requires explicit confirm
                }

                @Override
                public String getHashAlgorithm() {
                    return "SHA256"; // Upgraded from default SHA1 per requirements
                }

                @Override
                public int getHashMinRounds() {
                    return 5000; // Per CABackendParams-Kind-CMP.txt default
                }

                @Override
                public int getHashMaxRounds() {
                    return 10000; // Per CABackendParams-Kind-CMP.txt default
                }

                @Override
                public int getHashSaltSize() {
                    return 32; // Per CABackendParams-Kind-CMP.txt default
                }
            };
        }

        @Override
        public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
            // Same protection for upstream to EJBCA
            return getDownstreamConfiguration(certProfile, bodyType);
        }

        @Override
        public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
            return null; // Skipping certificate validation for PoC
        }

        @Override
        public boolean getForceRaVerifyOnUpstream(String certProfile, int bodyType) {
            return false;
        }

        @Override
        public InventoryInterface getInventory(String certProfile, int bodyType) {
            return null; // No inventory check
        }

        @Override
        public int getDownstreamTimeout(String certProfile, int bodyType) {
            return 60; // 60 seconds timeout
        }

        @Override
        public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
            return 10; // Poll retry after 10 seconds
        }

        @Override
        public SupportMessageHandlerInterface getSupportMessageHandler(String certProfile, int bodyType) {
            return null; // No support messages
        }

        @Override
        public boolean getRaVerifiedAcceptable(String certProfile, int bodyType) {
            return false;
        }
    }
}
