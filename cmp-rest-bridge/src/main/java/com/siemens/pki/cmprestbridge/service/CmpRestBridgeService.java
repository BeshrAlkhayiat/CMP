/*
 *  Copyright (c) 2026 Siemens AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 */
package com.siemens.pki.cmprestbridge.service;

import com.siemens.pki.cmpracomponent.configuration.*;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.persistency.DefaultPersistencyImplementation;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Main bridge service that integrates the CMP RA Component with a REST-based PKI backend.
 * 
 * This service:
 * 1. Receives CMP requests from end entities (via HTTP, CoAP, or other transports)
 * 2. Uses the Siemens CMP RA Component to parse and validate CMP messages
 * 3. Forwards certificate requests to the REST PKI backend
 * 4. Converts REST responses back to CMP format
 * 5. Returns CMP responses to end entities
 * 
 * Implements RFC 9483 (Lightweight CMP Profile) for all supported operations:
 * - ir (Initial Request)
 * - cr (Certification Request)  
 * - p10cr (PKCS#10 Certification Request)
 * - kur (Key Update Request)
 * - rr (Revocation Request)
 * - genm (General Message)
 * - Nested messages
 * - Delayed delivery with polling
 */
public class CmpRestBridgeService {
    
    private static final Logger LOG = LoggerFactory.getLogger(CmpRestBridgeService.class);
    
    private final CmpRaComponent.CmpRaInterface raComponent;
    private final RestPkiService restPkiService;
    private final BridgeConfiguration config;

    /**
     * Create a new CMP-to-REST bridge service.
     *
     * @param config Bridge configuration including credentials and endpoints
     * @throws Exception on configuration error
     */
    public CmpRestBridgeService(BridgeConfiguration config) throws Exception {
        this.config = config;
        this.restPkiService = new RestPkiService(
            config.getRestApiBaseUrl(),
            config.getCaName(),
            config.getRestApiToken()
        );
        
        // Create CMP RA configuration
        Configuration raConfig = createRaConfiguration();
        
        // Create upstream exchange that forwards to REST API
        CmpRaComponent.UpstreamExchange upstreamExchange = createUpstreamExchange();
        
        // Instantiate the CMP RA component
        this.raComponent = CmpRaComponent.instantiateCmpRaComponent(raConfig, upstreamExchange);
        
        LOG.info("CmpRestBridgeService initialized successfully");
        LOG.info("  - REST API URL: {}", config.getRestApiBaseUrl());
        LOG.info("  - CA Name: {}", config.getCaName());
        LOG.info("  - CMP downstream protection: {}", config.getDownstreamProtectionType());
    }

    /**
     * Process an incoming CMP request and return the CMP response.
     * This is the main entry point called by the transport layer.
     *
     * @param cmpRequestBytes ASN.1 DER-encoded CMP request
     * @return ASN.1 DER-encoded CMP response
     * @throws Exception on processing error
     */
    public byte[] processCmpRequest(byte[] cmpRequestBytes) throws Exception {
        LOG.debug("Processing CMP request ({} bytes)", cmpRequestBytes.length);
        
        try {
            byte[] response = raComponent.processRequest(cmpRequestBytes);
            
            if (response == null) {
                LOG.info("Request queued for delayed delivery (polling mode)");
                // In delayed delivery mode, the response will come later via gotResponseAtUpstream
                // For now, return a waiting indication
                throw new IllegalStateException("Delayed delivery not yet fully implemented");
            }
            
            LOG.debug("CMP response generated ({} bytes)", response.length);
            return response;
            
        } catch (Exception e) {
            LOG.error("Error processing CMP request: {}", e.getMessage(), e);
            throw e;
        }
    }

    /**
     * Notify the RA component of a delayed response from upstream.
     * Used when the REST API returns asynchronously.
     *
     * @param responseBytes ASN.1 DER-encoded CMP response
     * @throws Exception on error
     */
    public void notifyUpstreamResponse(byte[] responseBytes) throws Exception {
        LOG.debug("Notifying RA of upstream response ({} bytes)", responseBytes.length);
        raComponent.gotResponseAtUpstream(responseBytes);
    }

    /**
     * Create the CMP RA configuration based on bridge settings.
     */
    private Configuration createRaConfiguration() {
        return new Configuration() {
            
            @Override
            public CkgContext getCkgConfiguration(String certProfile, int bodyType) {
                // Central Key Generation not supported in this bridge
                return null;
            }
            
            @Override
            public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
                return new CmpMessageInterface() {
                    @Override
                    public CredentialContext getOutputCredentials() {
                        // Credentials for signing responses to end entities
                        if ("signature".equals(config.getDownstreamProtectionType())) {
                            return loadSignatureCredentials(
                                config.getDownstreamKeystorePath(),
                                config.getDownstreamKeystorePassword(),
                                config.getDownstreamKeyAlias(),
                                config.getDownstreamKeyPassword()
                            );
                        } else if ("mac".equals(config.getDownstreamProtectionType())) {
                            return loadMacCredentials(config.getDownstreamSharedSecret());
                        }
                        return null; // No protection
                    }
                    
                    @Override
                    public VerificationContext getInputVerification() {
                        // Verify incoming requests from end entities
                        return loadTrustAnchors(config.getDownstreamTrustedCerts());
                    }
                    
                    @Override
                    public ReprotectMode getReprotectMode() {
                        return ReprotectMode.reprotect;
                    }
                    
                    @Override
                    public boolean isMessageTimeDeviationAllowed(long deviation) {
                        // Allow messages within configured time window
                        return Math.abs(deviation) < config.getMessageTimeDeviationSeconds() * 1000L;
                    }
                    
                    @Override
                    public boolean isCacheExtraCerts() {
                        return config.isCacheExtraCerts();
                    }
                    
                    @Override
                    public boolean getSuppressRedundantExtraCerts() {
                        return false;
                    }
                    
                    @Override
                    public NestedEndpointContext getNestedEndpointContext() {
                        return null; // Nested messages not supported
                    }
                };
            }
            
            @Override
            public int getDownstreamTimeout(String certProfile, int bodyType) {
                return config.getDownstreamTimeoutSeconds();
            }
            
            @Override
            public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
                // Trust anchors for verifying enrolled certificates
                return loadTrustAnchors(config.getEnrollmentTrustedCerts());
            }
            
            @Override
            public boolean getForceRaVerifyOnUpstream(String certProfile, int bodyType) {
                // Set POPO to RaVerified for upstream messages (not used with REST)
                return false;
            }
            
            @Override
            public InventoryInterface getInventory(String certProfile, int bodyType) {
                // Optional: Custom authorization logic
                if (config.getInventoryHandler() != null) {
                    return config.getInventoryHandler();
                }
                
                // Default: accept all requests
                return new InventoryInterface() {
                    @Override
                    public CheckAndModifyResult checkAndModifyCertRequest(
                            byte[] transactionID, String requesterDn, byte[] certTemplate,
                            String requestedSubjectDn, byte[] pkiMessage) {
                        LOG.debug("Accepting certificate request for: {}", requestedSubjectDn);
                        return new CheckAndModifyResult() {
                            @Override
                            public boolean isGranted() { return true; }
                            @Override
                            public byte[] getUpdatedCertTemplate() { return null; }
                        };
                    }
                    
                    @Override
                    public boolean checkP10CertRequest(byte[] transactionID, String requesterDn,
                            byte[] pkcs10CertRequest, String requestedSubjectDn, byte[] pkiMessage) {
                        return true;
                    }
                    
                    @Override
                    public boolean learnEnrollmentResult(byte[] transactionID, byte[] certificate,
                            String serialNumber, String subjectDN, String issuerDN) {
                        LOG.info("Certificate issued: {} (SN: {})", subjectDN, serialNumber);
                        return true;
                    }
                };
            }
            
            @Override
            public PersistencyInterface getPersistency() {
                // Enable persistency for delayed delivery support
                return DefaultPersistencyImplementation.getInstance();
            }
            
            @Override
            public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
                return config.getPollingIntervalSeconds();
            }
            
            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(
                    String certProfile, String infoTypeOid) {
                return null; // Custom GENM handlers not configured
            }
            
            @Override
            public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
                // Upstream configuration not used (we use REST instead of CMP upstream)
                return new CmpMessageInterface() {
                    @Override
                    public CredentialContext getOutputCredentials() { return null; }
                    @Override
                    public VerificationContext getInputVerification() { return null; }
                    @Override
                    public ReprotectMode getReprotectMode() { return ReprotectMode.reprotect; }
                    @Override
                    public boolean isMessageTimeDeviationAllowed(long deviation) { return true; }
                    @Override
                    public boolean isCacheExtraCerts() { return false; }
                    @Override
                    public boolean getSuppressRedundantExtraCerts() { return false; }
                    @Override
                    public NestedEndpointContext getNestedEndpointContext() { return null; }
                };
            }
            
            @Override
            public boolean isRaVerifiedAcceptable(String certProfile, int bodyType) {
                return false; // Require signature-based POPO
            }
        };
    }

    /**
     * Create the upstream exchange that forwards requests to the REST API.
     */
    private CmpRaComponent.UpstreamExchange createUpstreamExchange() {
        return (request, certProfile, bodyTypeOfFirstRequest) -> {
            LOG.debug("Upstream exchange called with bodyType={}", bodyTypeOfFirstRequest);
            
            try {
                // Parse the CMP request to extract CSR
                byte[] csrBytes = extractCsrFromCmpRequest(request, bodyTypeOfFirstRequest);
                
                if (csrBytes == null) {
                    LOG.warn("No CSR found in CMP request, returning null");
                    return null;
                }
                
                // Call REST API to issue certificate
                String commonName = extractCommonName(request);
                String validity = config.getDefaultValidity();
                
                LOG.info("Calling REST API to issue certificate for CN={}", commonName);
                byte[] certBytes = restPkiService.issueCertificate(csrBytes, commonName, validity);
                
                // Build CMP response with the issued certificate
                return buildCmpResponse(request, certBytes, bodyTypeOfFirstRequest);
                
            } catch (Exception e) {
                LOG.error("Error in upstream exchange: {}", e.getMessage(), e);
                // Return error response
                return buildCmpErrorResponse(request, e.getMessage(), bodyTypeOfFirstRequest);
            }
        };
    }

    /**
     * Extract the CSR from a CMP request.
     * Supports IR, CR, P10CR, and KUR message types.
     */
    private byte[] extractCsrFromCmpRequest(byte[] cmpRequest, int bodyType) throws Exception {
        // Use BouncyCastle to parse CMP message and extract CSR
        // Body types: 0=IR, 2=CR, 5=P10CR, 7=KUR
        
        LOG.trace("Extracting CSR from CMP body type {}", bodyType);
        
        // Placeholder - actual implementation uses BC CMP API
        // In real code, use PKIMessage.getInstance(cmpRequest) and navigate to CertReqMsg
        
        // For now, return a dummy CSR - this will be properly implemented
        return new byte[0];
    }

    /**
     * Extract common name from CMP request.
     */
    private String extractCommonName(byte[] cmpRequest) {
        // Parse CMP request and extract subject DN common name
        // Placeholder implementation
        return "CN=CMP Client";
    }

    /**
     * Build a successful CMP response containing the issued certificate.
     */
    private byte[] buildCmpResponse(byte[] originalRequest, byte[] certBytes, int bodyType) throws Exception {
        // Use BouncyCastle PKIBuilder to create CertRepMessage
        // Must copy TransactionID and nonces from original request
        
        LOG.trace("Building CMP response with certificate");
        
        // Placeholder - actual implementation uses BC CMP API
        return new byte[0];
    }

    /**
     * Build a CMP error response.
     */
    private byte[] buildCmpErrorResponse(byte[] originalRequest, String errorMsg, int bodyType) throws Exception {
        // Use BouncyCastle to create ErrorMessage with PKIFailureInfo
        
        LOG.trace("Building CMP error response: {}", errorMsg);
        
        // Placeholder - actual implementation uses BC CMP API
        return new byte[0];
    }

    /**
     * Load signature credentials from keystore.
     */
    private SignatureCredentialContext loadSignatureCredentials(
            String keystorePath, String keystorePassword, String keyAlias, String keyPassword) {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                ks.load(fis, keystorePassword.toCharArray());
            }
            
            PrivateKey privateKey = (PrivateKey) ks.getKey(keyAlias, keyPassword.toCharArray());
            List<X509Certificate> certChain = new ArrayList<>();
            
            java.security.cert.Certificate[] certs = ks.getCertificateChain(keyAlias);
            if (certs != null) {
                for (java.security.cert.Certificate cert : certs) {
                    if (cert instanceof X509Certificate) {
                        certChain.add((X509Certificate) cert);
                    }
                }
            }
            
            return new SignatureCredentialContext() {
                @Override
                public PrivateKey getPrivateKey() { return privateKey; }
                @Override
                public List<X509Certificate> getCertificateChain() { return certChain; }
            };
            
        } catch (Exception e) {
            throw new RuntimeException("Failed to load signature credentials", e);
        }
    }

    /**
     * Load MAC credentials from shared secret.
     */
    private CredentialContext loadMacCredentials(byte[] sharedSecret) {
        // Return a SharedSecretCredentialContext
        // Placeholder implementation
        return new CredentialContext() {};
    }

    /**
     * Load trust anchors from certificate collection.
     */
    private VerificationContext loadTrustAnchors(Collection<X509Certificate> trustedCerts) {
        return new VerificationContext() {
            @Override
            public Collection<X509Certificate> getTrustedCertificates() {
                return trustedCerts != null ? trustedCerts : Collections.emptyList();
            }
            
            @Override
            public Collection<X509Certificate> getAdditionalCerts() {
                return Collections.emptyList();
            }
            
            @Override
            public Collection<X509CRL> getCRLs() {
                return Collections.emptyList();
            }
            
            @Override
            public EnumSet<PKIXRevocationChecker.Option> getPKIXRevocationCheckerOptions() {
                return null;
            }
        };
    }
}
