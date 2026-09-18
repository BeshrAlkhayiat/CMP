/*
 *  Copyright (c) 2024 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 */
package com.siemens.pki.cmpgateway.config;

import com.siemens.pki.cmpracomponent.configuration.*;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

/**
 * Gateway configuration loaded from properties file.
 */
public class GatewayConfig implements Configuration {
    
    private static final Logger LOG = LoggerFactory.getLogger(GatewayConfig.class);
    
    // REST API configuration
    private String restBaseUrl;
    private String caName;
    private String tplName;
    private String lookupName;
    
    // Authentication configuration
    private String authType; // "certificate" or "basic"
    private String keystorePath;
    private String keystorePassword;
    private String keyAlias;
    private String username;
    private String password;
    
    // CMP protection configuration
    private byte[] sharedSecret;
    
    // Timeouts
    private int retryAfterSeconds;
    private int downstreamTimeoutSeconds;
    
    public GatewayConfig() {
        // Defaults
        this.restBaseUrl = "https://localhost:5443/cema/ccm/svc/db.file/rest/v2";
        this.caName = "TEST_CA";
        this.tplName = "DEFAULT_TEMPLATE";
        this.lookupName = "default";
        this.authType = "certificate";
        this.retryAfterSeconds = 30;
        this.downstreamTimeoutSeconds = 300;
        this.sharedSecret = "gateway-secret-key".getBytes();
    }
    
    // Getters and setters
    public String getRestBaseUrl() { return restBaseUrl; }
    public void setRestBaseUrl(String restBaseUrl) { this.restBaseUrl = restBaseUrl; }
    
    public String getCaName() { return caName; }
    public void setCaName(String caName) { this.caName = caName; }
    
    public String getTplName() { return tplName; }
    public void setTplName(String tplName) { this.tplName = tplName; }
    
    public String getLookupName() { return lookupName; }
    public void setLookupName(String lookupName) { this.lookupName = lookupName; }
    
    public String getAuthType() { return authType; }
    public void setAuthType(String authType) { this.authType = authType; }
    
    public String getKeystorePath() { return keystorePath; }
    public void setKeystorePath(String keystorePath) { this.keystorePath = keystorePath; }
    
    public String getKeystorePassword() { return keystorePassword; }
    public void setKeystorePassword(String keystorePassword) { this.keystorePassword = keystorePassword; }
    
    public String getKeyAlias() { return keyAlias; }
    public void setKeyAlias(String keyAlias) { this.keyAlias = keyAlias; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    
    public byte[] getSharedSecret() { return sharedSecret; }
    public void setSharedSecret(byte[] sharedSecret) { this.sharedSecret = sharedSecret; }
    
    public int getRetryAfterSeconds() { return retryAfterSeconds; }
    public void setRetryAfterSeconds(int retryAfterSeconds) { this.retryAfterSeconds = retryAfterSeconds; }
    
    public int getDownstreamTimeoutSeconds() { return downstreamTimeoutSeconds; }
    public void setDownstreamTimeoutSeconds(int downstreamTimeoutSeconds) { this.downstreamTimeoutSeconds = downstreamTimeoutSeconds; }
    
    /**
     * Load PKCS#12 keystore and extract certificate chain and private key.
     */
    public KeyStore loadKeyStore() throws Exception {
        if (keystorePath == null || keystorePath.isEmpty()) {
            return null;
        }
        KeyStore ks = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            ks.load(fis, keystorePassword.toCharArray());
        }
        return ks;
    }
    
    public List<X509Certificate> getCertificateChain() throws Exception {
        KeyStore ks = loadKeyStore();
        if (ks == null) {
            return Collections.emptyList();
        }
        java.security.cert.Certificate[] certs = ks.getCertificateChain(keyAlias);
        if (certs == null) {
            return Collections.emptyList();
        }
        List<X509Certificate> result = new java.util.ArrayList<>();
        for (java.security.cert.Certificate cert : certs) {
            if (cert instanceof X509Certificate) {
                result.add((X509Certificate) cert);
            }
        }
        return result;
    }
    
    public PrivateKey getPrivateKey() throws Exception {
        KeyStore ks = loadKeyStore();
        if (ks == null) {
            return null;
        }
        return (PrivateKey) ks.getKey(keyAlias, keystorePassword.toCharArray());
    }
    
    // Configuration interface implementation
    
    @Override
    public CkgContext getCkgConfiguration(String certProfile, int bodyType) {
        // Central key generation not supported in gateway mode
        return null;
    }
    
    @Override
    public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
        // Downstream uses MAC-based protection with shared secret
        return new CmpMessageInterface() {
            @Override
            public VerificationContext getInputVerification() {
                // Accept both signature and MAC-based protection from EEs
                return new VerificationContext() {
                    @Override
                    public byte[] getSharedSecret(byte[] senderKID) {
                        return sharedSecret;
                    }
                    
                    @Override
                    public Collection<X509Certificate> getTrustedCertificates() {
                        return Collections.emptyList(); // Accept all for now
                    }
                };
            }
            
            @Override
            public NestedEndpointContext getNestedEndpointContext() {
                return null;
            }
            
            @Override
            public CredentialContext getOutputCredentials() {
                // Respond with same MAC protection
                return new SharedSecretCredentialContext() {
                    @Override
                    public byte[] getSharedSecret() {
                        return sharedSecret;
                    }
                };
            }
            
            @Override
            public ReprotectMode getReprotectMode() {
                return ReprotectMode.reprotect;
            }
            
            @Override
            public boolean getSuppressRedundantExtraCerts() {
                return false;
            }
            
            @Override
            public boolean isCacheExtraCerts() {
                return true;
            }
            
            @Override
            public boolean isMessageTimeDeviationAllowed(long deviation) {
                return Math.abs(deviation) < 300; // Allow 5 minutes deviation
            }
        };
    }
    
    @Override
    public int getDownstreamTimeout(String certProfile, int bodyType) {
        return downstreamTimeoutSeconds;
    }
    
    @Override
    public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
        // Trust context for validating enrolled certificates
        return new VerificationContext() {
            @Override
            public Collection<X509Certificate> getTrustedCertificates() {
                return Collections.emptyList(); // Configure as needed
            }
        };
    }
    
    @Override
    public boolean getForceRaVerifyOnUpstream(String certProfile, int bodyType) {
        // Set POPO to RaVerified for upstream requests
        return true;
    }
    
    @Override
    public InventoryInterface getInventory(String certProfile, int bodyType) {
        // No external inventory for now
        return null;
    }
    
    @Override
    public PersistencyInterface getPersistency() {
        // In-memory persistency (default)
        return new PersistencyInterface() {};
    }
    
    @Override
    public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
        return retryAfterSeconds;
    }
    
    @Override
    public SupportMessageHandlerInterface getSupportMessageHandler(String certProfile, String infoTypeOid) {
        // No custom support message handlers
        return null;
    }
    
    @Override
    public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
        // Upstream uses signature-based protection with gateway certificate
        return new CmpMessageInterface() {
            @Override
            public VerificationContext getInputVerification() {
                // Verify responses from CA
                return new VerificationContext() {
                    @Override
                    public List<X509Certificate> getTrustAnchors() {
                        return Collections.emptyList(); // Configure as needed
                    }
                    
                    @Override
                    public List<X509Certificate> getIntermediateCertificates() {
                        return Collections.emptyList();
                    }
                };
            }
            
            @Override
            public NestedEndpointContext getNestedEndpointContext() {
                return null;
            }
            
            @Override
            public CredentialContext getOutputCredentials() {
                // Sign upstream requests with gateway certificate
                try {
                    List<X509Certificate> certs = getCertificateChain();
                    PrivateKey privKey = getPrivateKey();
                    if (certs != null && !certs.isEmpty() && privKey != null) {
                        return new SignatureCredentialContext() {
                            @Override
                            public List<X509Certificate> getCertificateChain() {
                                return certs;
                            }
                            
                            @Override
                            public PrivateKey getPrivateKey() {
                                return privKey;
                            }
                        };
                    }
                } catch (Exception e) {
                    LOG.warn("Failed to load gateway certificate for upstream protection", e);
                }
                return null; // No protection if no certificate available
            }
            
            @Override
            public ReprotectMode getReprotectMode() {
                return ReprotectMode.reprotect;
            }
        };
    }
    
    @Override
    public boolean isRaVerifiedAcceptable(String certProfile, int bodyType) {
        // Accept RaVerified POPO from upstream
        return true;
    }
}
