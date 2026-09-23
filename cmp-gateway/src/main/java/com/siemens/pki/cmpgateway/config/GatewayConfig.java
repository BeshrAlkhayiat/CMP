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
import java.util.Collection;
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
    private String truststorePath;
    private String truststorePassword;
    private String truststoreType;
    private String username;
    private String password;
    private String loginUser;
    
    // CMP protection configuration
    private byte[] sharedSecret;
    
    // Timeouts
    private int retryAfterSeconds;
    private int downstreamTimeoutSeconds;
    private int cmpPort;
    private String cmpPath;
    private String centralKeyKind;
    private Integer centralKeySize;
    private String centralKeyCurve;
    private boolean crmfEnabled;
    
    public GatewayConfig() {
        // Defaults
        this.restBaseUrl = "https://localhost:5443/cema/ccm/svc/db.file/rest/v2";
        this.caName = "TEST_CA";
        this.tplName = "DEFAULT_TEMPLATE";
        this.lookupName = "default";
        this.authType = "certificate";
        this.retryAfterSeconds = 30;
        this.downstreamTimeoutSeconds = 300;
        this.cmpPort = 9000;
        this.cmpPath = "/cmp";
        this.centralKeyKind = "RSA";
        this.centralKeySize = 2048;
        // The CEMA REST API currently supports PKCS#10 (CSR) enrollment only,
        // so CRMF handling is disabled by default.
        this.crmfEnabled = false;
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
    public String getTruststorePath() { return truststorePath; }
    public void setTruststorePath(String truststorePath) { this.truststorePath = truststorePath; }
    public String getTruststorePassword() { return truststorePassword; }
    public void setTruststorePassword(String truststorePassword) { this.truststorePassword = truststorePassword; }
    public String getTruststoreType() { return truststoreType; }
    public void setTruststoreType(String truststoreType) { this.truststoreType = truststoreType; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getLoginUser() { return loginUser; }
    public void setLoginUser(String loginUser) { this.loginUser = loginUser; }
    
    public byte[] getSharedSecret() { return sharedSecret; }
    public void setSharedSecret(byte[] sharedSecret) { this.sharedSecret = sharedSecret; }
    
    public int getRetryAfterSeconds() { return retryAfterSeconds; }
    public void setRetryAfterSeconds(int retryAfterSeconds) { this.retryAfterSeconds = retryAfterSeconds; }
    
    public int getDownstreamTimeoutSeconds() { return downstreamTimeoutSeconds; }
    public void setDownstreamTimeoutSeconds(int downstreamTimeoutSeconds) { this.downstreamTimeoutSeconds = downstreamTimeoutSeconds; }
    public int getCmpPort() { return cmpPort; }
    public void setCmpPort(int cmpPort) { this.cmpPort = cmpPort; }
    public String getCmpPath() { return cmpPath; }
    public void setCmpPath(String cmpPath) { this.cmpPath = cmpPath; }
    public String getCentralKeyKind() { return centralKeyKind; }
    public void setCentralKeyKind(String centralKeyKind) { this.centralKeyKind = centralKeyKind; }
    public Integer getCentralKeySize() { return centralKeySize; }
    public void setCentralKeySize(Integer centralKeySize) { this.centralKeySize = centralKeySize; }
    public String getCentralKeyCurve() { return centralKeyCurve; }
    public void setCentralKeyCurve(String centralKeyCurve) { this.centralKeyCurve = centralKeyCurve; }
    public boolean isCrmfEnabled() { return crmfEnabled; }
    public void setCrmfEnabled(boolean crmfEnabled) { this.crmfEnabled = crmfEnabled; }
    
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

    public KeyStore loadTrustStore() throws Exception {
        if (truststorePath == null || truststorePath.isEmpty()) {
            return null;
        }
        KeyStore trustStore = KeyStore.getInstance(
                truststoreType == null || truststoreType.isEmpty() ? KeyStore.getDefaultType() : truststoreType);
        try (FileInputStream fis = new FileInputStream(truststorePath)) {
            trustStore.load(fis, truststorePassword == null ? null : truststorePassword.toCharArray());
        }
        return trustStore;
    }
    
    /**
     * Extract all X.509 certificates from the configured truststore to be used as
     * trust anchors when validating signature-based CMP protection (e.g. upstream
     * responses signed by the CA). Returns an empty list if no truststore is configured.
     */
    public List<X509Certificate> getTrustedCertificatesFromTrustStore() {
        if (truststorePath == null || truststorePath.isEmpty()) {
            return Collections.emptyList();
        }
        try {
            KeyStore ts = loadTrustStore();
            if (ts == null) {
                return Collections.emptyList();
            }
            List<X509Certificate> result = new java.util.ArrayList<>();
            java.util.Enumeration<String> aliases = ts.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                if (ts.isCertificateEntry(alias)) {
                    java.security.cert.Certificate cert = ts.getCertificate(alias);
                    if (cert instanceof X509Certificate) {
                        result.add((X509Certificate) cert);
                    }
                } else if (ts.isKeyEntry(alias)) {
                    java.security.cert.Certificate[] chain = ts.getCertificateChain(alias);
                    if (chain != null) {
                        for (java.security.cert.Certificate cert : chain) {
                            if (cert instanceof X509Certificate) {
                                result.add((X509Certificate) cert);
                            }
                        }
                    }
                }
            }
            LOG.info("Loaded " + result.size() + " trusted certificate(s) from truststore '"
                    + truststorePath + "'");
            return result;
        } catch (Exception e) {
            LOG.warn("could not load truststore '" + truststorePath + "' for CMP protection validation", e);
            return Collections.emptyList();
        }
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
        return new CkgContext() {
            @Override
            public CkgKeyAgreementContext getKeyAgreementContext() {
                return null;
            }

            @Override
            public CkgKeyTransportContext getKeyTransportContext() {
                return new CkgKeyTransportContext() {};
            }

            @Override
            public CkgPasswordContext getPasswordContext() {
                return new CkgPasswordContext() {
                    @Override
                    public SharedSecretCredentialContext getEncryptionCredentials() {
                        return new SharedSecretCredentialContext() {
                            @Override
                            public byte[] getSharedSecret() {
                                return sharedSecret;
                            }
                        };
                    }
                };
            }

            @Override
            public SignatureCredentialContext getSigningCredentials() {
                try {
                    final List<X509Certificate> chain = getCertificateChain();
                    final PrivateKey key = getPrivateKey();
                    if (chain.isEmpty() || key == null) {
                        throw new IllegalStateException(
                                "central key generation requires gateway signing credentials");
                    }
                    return new SignatureCredentialContext() {
                        @Override
                        public List<X509Certificate> getCertificateChain() {
                            return chain;
                        }

                        @Override
                        public PrivateKey getPrivateKey() {
                            return key;
                        }
                    };
                } catch (Exception exception) {
                    throw new IllegalStateException(
                            "could not load gateway signing credentials for central key generation", exception);
                }
            }
        };
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
                        // Trust anchors for signature-protected downstream requests.
                        // null disables certificate-path validation (accept any signer);
                        // an empty collection would make PKIX path building fail with
                        // "the trustAnchors parameter must be non-empty".
                        return null;
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
                // No enrollment trust configured: return null to skip certificate-path
                // validation instead of an empty list (which breaks PKIX path building).
                return null;
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
                    public Collection<X509Certificate> getTrustedCertificates() {
                        // Trust anchors for validating signature-protected upstream
                        // responses: the certificates from the configured truststore.
                        // If none are configured, return null to skip path validation
                        // rather than an empty list, which fails with
                        // "the trustAnchors parameter must be non-empty".
                        List<X509Certificate> trusted = getTrustedCertificatesFromTrustStore();
                        return trusted.isEmpty() ? null : trusted;
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
                return Math.abs(deviation) < 300;
            }
        };
    }
    
    @Override
    public boolean isRaVerifiedAcceptable(String certProfile, int bodyType) {
        // Accept RaVerified POPO from upstream
        return true;
    }
}
