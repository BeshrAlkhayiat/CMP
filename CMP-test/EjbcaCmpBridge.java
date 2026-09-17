import com.siemens.pki.cmpracomponent.configuration.*;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

/**
 * PoC: Bridge between OpenSSL CMP client and EJBCA CMP server.
 * 
 * ARCHITECTURE (Mode A - Pass-Through):
 * [OpenSSL CMP] --> [This Bridge (RA Component)] --> [EJBCA CMP Server]
 * 
 * The bridge accepts CMP messages on port 8080, forwards them to EJBCA via HTTP POST,
 * and returns the response. All CMP protocol handling is done by the RA Component.
 * 
 * CONFIGURATION MAPPING (from CABackendParams-Kind-CMP.txt):
 * - CMP.EndpointAddress -> ejbcaUrl (passed as argument)
 * - AuthenticationSharedSecret -> sharedSecret (passed as argument)
 * - CMP.Sender.KID -> senderKID (passed as argument)
 * - CMP.HashAlgorithm -> SHA256 (configured below)
 * - CMP.ImplicitConfirm -> false (configured below)
 * - CMP.HashMinRounds -> 5000 (configured below)
 * - CMP.HashSaltSize -> 32 (configured below)
 */
public class EjbcaCmpBridge {
    
    private static final int DOWNSTREAM_PORT = 8080;
    private static final String DOWNSTREAM_PATH = "/cmp";
    
    private final String ejbcaUrl;
    private final byte[] sharedSecret;
    private final byte[] senderKID;
    private final CmpRaInterface raComponent;
    private final HttpClient httpClient;

    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.err.println("Usage: java EjbcaCmpBridge <ejbcaUrl> <sharedSecret> <senderKID>");
            System.err.println("Example: java EjbcaCmpBridge http://localhost:8080/ejbca/publicweb/cmp/myalias mySecret myKeyId");
            System.exit(1);
        }
        
        String ejbcaUrl = args[0];
        String sharedSecret = args[1];
        String senderKID = args[2];
        
        EjbcaCmpBridge bridge = new EjbcaCmpBridge(ejbcaUrl, sharedSecret, senderKID);
        bridge.start();
    }

    public EjbcaCmpBridge(String ejbcaUrl, String sharedSecret, String senderKID) throws Exception {
        this.ejbcaUrl = ejbcaUrl;
        this.sharedSecret = sharedSecret.getBytes(StandardCharsets.UTF_8);
        this.senderKID = senderKID.getBytes(StandardCharsets.UTF_8);
        this.httpClient = HttpClient.newHttpClient();
        
        // Create configuration for EJBCA
        Configuration config = new EjbcConfiguration();
        
        // Create upstream exchange that forwards to EJBCA
        UpstreamExchange upstreamExchange = this::forwardToEjbca;
        
        // Initialize RA Component using the static factory method
        this.raComponent = CmpRaComponent.instantiateCmpRaComponent(config, upstreamExchange);
        
        System.out.println("EJBCA CMP Bridge initialized");
        System.out.println("  EJBCA URL: " + ejbcaUrl);
        System.out.println("  Downstream port: " + DOWNSTREAM_PORT);
        System.out.println("  Downstream path: " + DOWNSTREAM_PATH);
        System.out.println("  Hash Algorithm: SHA256");
        System.out.println("  Implicit Confirm: false");
        System.out.println("  Hash Rounds: 5000");
        System.out.println("  Salt Size: 32 bytes");
    }

    public void start() throws Exception {
        // Simple HTTP server to accept CMP requests from OpenSSL
        com.sun.net.httpserver.HttpServer server = com.sun.net.httpserver.HttpServer.create(
            new java.net.InetSocketAddress(DOWNSTREAM_PORT), 0);
        
        server.createContext(DOWNSTREAM_PATH, exchange -> {
            try {
                // Read incoming CMP request
                byte[] requestBytes = exchange.getRequestBody().readAllBytes();
                System.out.println("Received CMP request: " + requestBytes.length + " bytes");
                
                // Process through RA Component
                byte[] responseBytes = raComponent.processRequest(requestBytes);
                
                // Send response back
                exchange.sendResponseHeaders(200, responseBytes.length);
                exchange.getResponseBody().write(responseBytes);
                exchange.close();
                
                System.out.println("Sent CMP response: " + responseBytes.length + " bytes");
            } catch (Exception e) {
                System.err.println("Error processing request: " + e.getMessage());
                e.printStackTrace();
                exchange.sendResponseHeaders(500, -1);
                exchange.close();
            }
        });
        
        server.setExecutor(null);
        server.start();
        
        System.out.println("\nEJBCA CMP Bridge started on port " + DOWNSTREAM_PORT);
        System.out.println("Ready to accept CMP requests at http://localhost:" + DOWNSTREAM_PORT + DOWNSTREAM_PATH);
        System.out.println("\nExample OpenSSL commands:");
        System.out.println("  # Initialize Request (IR):");
        System.out.println("  openssl cmp -server http://localhost:" + DOWNSTREAM_PORT + DOWNSTREAM_PATH + " \\");
        System.out.println("    -cacerts ejbca_ca.pem -certout cert.pem -keyout key.pem \\");
        System.out.println("    -subject \"/CN=TestUser/O=MyOrg\" -ir \\");
        System.out.println("    -secret " + new String(sharedSecret) + " -kid " + new String(senderKID) + " -digest sha256");
        System.out.println("\n  # PKCS#10 Certificate Request (P10CR):");
        System.out.println("  openssl cmp -server http://localhost:" + DOWNSTREAM_PORT + DOWNSTREAM_PATH + " \\");
        System.out.println("    -cacerts ejbca_ca.pem -certout issued_cert.pem \\");
        System.out.println("    -p10cr user.csr \\");
        System.out.println("    -secret " + new String(sharedSecret) + " -kid " + new String(senderKID) + " -digest sha256");
    }

    /**
     * Forward CMP message to EJBCA via HTTP POST
     */
    private byte[] forwardToEjbca(byte[] requestBytes, String certProfile, int bodyType) throws Exception {
        System.out.println("Forwarding " + requestBytes.length + " bytes to EJBCA: " + ejbcaUrl + 
                          " (bodyType=" + bodyType + ", certProfile=" + certProfile + ")");
        
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(ejbcaUrl))
            .header("Content-Type", "application/pkixcmp")
            .POST(HttpRequest.BodyPublishers.ofByteArray(requestBytes))
            .build();
        
        HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
        
        int statusCode = response.statusCode();
        byte[] responseBody = response.body();
        
        System.out.println("EJBCA response: status=" + statusCode + ", size=" + responseBody.length + " bytes");
        
        if (statusCode != 200) {
            throw new IOException("EJBCA returned status code: " + statusCode);
        }
        
        return responseBody;
    }

    /**
     * Configuration implementation for EJBCA based on CABackendParams-Kind-CMP.txt
     */
    class EjbcConfiguration implements Configuration {
        
        // Shared secret credential context for MAC protection (upstream to EJBCA)
        private final SharedSecretCredentialContext upstreamCredentials = new SharedSecretCredentialContext() {
            @Override
            public byte[] getSharedSecret() {
                return sharedSecret;
            }
            
            @Override
            public byte[] getSenderKID() {
                return senderKID;
            }
            
            @Override
            public String getMacAlgorithm() {
                // Use HMAC-SHA256 as per CMP.HashAlgorithm: SHA256
                return PKCSObjectIdentifiers.id_hmacWithSHA256.getId();
            }
            
            @Override
            public String getPasswordBasedMacAlgorithm() {
                return "PBMAC1";
            }
            
            @Override
            public String getPrf() {
                return "SHA256";
            }
            
            @Override
            public int getIterationCount() {
                // From CMP.HashMinRounds: 5000
                return 5000;
            }
            
            @Override
            public byte[] getSalt() {
                // From CMP.HashSaltSize: 32
                return new byte[32];
            }
        };
        
        // Verification context for downstream (accept MAC from OpenSSL clients)
        private final VerificationContext downstreamVerification = new VerificationContext() {
            @Override
            public byte[] getSharedSecret(byte[] senderKID) {
                // Accept the same shared secret from all clients
                // In production, you might want to look up different secrets per KID
                return sharedSecret;
            }
            
            @Override
            public Collection<X509Certificate> getTrustedCertificates() {
                // Optionally add CA certificates for signature verification
                return Collections.emptyList();
            }
        };

        @Override
        public CkgContext getCkgConfiguration(String certProfile, int bodyType) {
            return null; // No central key generation
        }

        @Override
        public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
            return new CmpMessageInterface() {
                @Override
                public VerificationContext getInputVerification() {
                    return downstreamVerification;
                }

                @Override
                public NestedEndpointContext getNestedEndpointContext() {
                    return null; // No nested messages
                }

                @Override
                public CredentialContext getOutputCredentials() {
                    return null; // Response protection handled automatically for MAC
                }

                @Override
                public ReprotectMode getReprotectMode() {
                    return ReprotectMode.keep; // Keep MAC protection on responses
                }

                @Override
                public boolean getSuppressRedundantExtraCerts() {
                    return false;
                }

                @Override
                public boolean isCacheExtraCerts() {
                    return true; // Cache certificates for polling
                }

                @Override
                public boolean isMessageTimeDeviationAllowed(long deviation) {
                    return Math.abs(deviation) <= 300; // Allow 5 minutes deviation
                }
            };
        }

        @Override
        public int getDownstreamTimeout(String certProfile, int bodyType) {
            return 300; // 5 minutes timeout
        }

        @Override
        public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
            return null; // No enrollment trust validation in pass-through mode
        }

        @Override
        public boolean getForceRaVerifyOnUpstream(String certProfile, int bodyType) {
            return false; // Don't force RaVerified for EJBCA
        }

        @Override
        public InventoryInterface getInventory(String certProfile, int bodyType) {
            return null; // No inventory check
        }

        @Override
        public PersistencyInterface getPersistency() {
            return new PersistencyInterface() {}; // No persistence needed
        }

        @Override
        public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
            return 10; // Poll every 10 seconds if delayed
        }

        @Override
        public SupportMessageHandlerInterface getSupportMessageHandler(String certProfile, String infoTypeOid) {
            return null; // No GENM support needed
        }

        @Override
        public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
            return new CmpMessageInterface() {
                @Override
                public VerificationContext getInputVerification() {
                    return null; // Don't verify EJBCA responses (trust the channel)
                }

                @Override
                public NestedEndpointContext getNestedEndpointContext() {
                    return null;
                }

                @Override
                public CredentialContext getOutputCredentials() {
                    return upstreamCredentials; // Protect requests to EJBCA with MAC
                }

                @Override
                public ReprotectMode getReprotectMode() {
                    return ReprotectMode.reprotect; // Always protect outgoing messages
                }

                @Override
                public boolean getSuppressRedundantExtraCerts() {
                    return false;
                }

                @Override
                public boolean isCacheExtraCerts() {
                    return false;
                }

                @Override
                public boolean isMessageTimeDeviationAllowed(long deviation) {
                    return true; // Allow any time deviation for EJBCA
                }
            };
        }

        @Override
        public boolean isRaVerifiedAcceptable(String certProfile, int bodyType) {
            return false; // Require proper POPO (Proof of Possession)
        }
    }
}
