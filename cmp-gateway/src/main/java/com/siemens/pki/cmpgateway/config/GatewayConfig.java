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

    /**
     * Cache for the truststore contents: reading the PKCS#12 file on every CMP
     * message is expensive and produces repeated log noise. Cleared whenever a
     * new truststore path is configured.
     */
    private List<X509Certificate> cachedTrustedCertificates;
    
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
    public void setTruststorePath(String truststorePath) {
        this.truststorePath = truststorePath;
        this.cachedTrustedCertificates = null; // invalidate cache on reconfiguration
    }
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
        if (cachedTrustedCertificates != null) {
            return cachedTrustedCertificates;
        }
        if (truststorePath == null || truststorePath.isEmpty()) {
            LOG.debug("no truststore configured (auth.truststore.path is empty); "
                    + "upstream protection-certificate path validation will be skipped");
            return Collections.emptyList();
        }
        java.io.File tsFile = new java.io.File(truststorePath);
        if (!tsFile.isFile()) {
            // Fail loudly: a missing truststore file usually means a typo in
            // auth.truststore.path or that the file was never exported. Without it,
            // signature-protected upstream messages cannot be validated against trust.
            LOG.warn("truststore file '" + tsFile.getAbsolutePath()
                    + "' does not exist; upstream protection-certificate path validation "
                    + "will be skipped. Fix auth.truststore.path or leave it empty to skip intentionally.");
            cachedTrustedCertificates = Collections.emptyList();
            return cachedTrustedCertificates;
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
            for (X509Certificate cert : result) {
                LOG.debug("trust anchor: subject='" + cert.getSubjectX500Principal()
                        + "', issuer='" + cert.getIssuerX500Principal()
                        + "', notBefore=" + cert.getNotBefore()
                        + ", notAfter=" + cert.getNotAfter());
            }
            cachedTrustedCertificates = result;
            return result;
        } catch (Exception e) {
            LOG.warn("could not load truststore '" + truststorePath + "' for CMP protection validation", e);
            return Collections.emptyList();
        }
    }

    /**
     * Trust anchors for validating signature-protected upstream (CA) CMP responses.
     * Injected by Main after the REST client is created, so the gateway can fetch
     * them automatically from CEMA (GET /ca/{caName}/chain) instead of requiring a
     * manually exported truststore file. May be null before injection.
     */
    private volatile java.util.function.Supplier<List<X509Certificate>> upstreamTrustSupplier;

    public void setUpstreamTrustSupplier(
            java.util.function.Supplier<List<X509Certificate>> upstreamTrustSupplier) {
        this.upstreamTrustSupplier = upstreamTrustSupplier;
        // Invalidate any cached result so the new source takes effect immediately.
        this.cachedAutomaticCaChain = null;
        LOG.debug("upstream trust anchor supplier configured (automatic CA chain via GET /ca/{}/chain)",
                caName);
    }

    /** Cache for the automatically fetched CA chain; failures are retried on next access. */
    private volatile List<X509Certificate> cachedAutomaticCaChain;

    /**
     * Automatic trust anchors: the CA certificate chain fetched from CEMA via
     * GET /ca/{caName}/chain (through the supplier injected above). Returns an empty
     * list if no supplier is set or the fetch fails - the caller then falls back to
     * the file-based truststore or skips path validation.
     */
    public List<X509Certificate> getAutomaticallyFetchedCaChain() {
        java.util.function.Supplier<List<X509Certificate>> supplier = this.upstreamTrustSupplier;
        if (supplier == null) {
            return Collections.emptyList();
        }
        List<X509Certificate> cached = this.cachedAutomaticCaChain;
        if (cached != null) {
            return cached;
        }
        try {
            List<X509Certificate> chain = supplier.get();
            if (chain != null && !chain.isEmpty()) {
                this.cachedAutomaticCaChain = chain;
                return chain;
            }
            LOG.warn("automatic CA chain fetch returned no certificates");
        } catch (Exception e) {
            LOG.warn("could not fetch the CA chain automatically from CEMA "
                    + "(GET /ca/" + caName + "/chain); falling back to the file truststore", e);
        }
        return Collections.emptyList();
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

    /**
     * The gateway's own signature-protection certificate (leaf of the configured
     * key-store chain), as an ASN.1 structure for embedding in CMP messages
     * (e.g. id-it-caProtEncCert general-message answers). Returns {@code null}
     * if no signer certificate is available.
     */
    public org.bouncycastle.asn1.x509.Certificate getSignerCertificateOrNull() {
        try {
            List<X509Certificate> chain = getCertificateChain();
            if (chain.isEmpty()) {
                return null;
            }
            return org.bouncycastle.asn1.x509.Certificate.getInstance(
                    org.bouncycastle.asn1.ASN1Primitive.fromByteArray(
                            chain.get(0).getEncoded()));
        } catch (Exception e) {
            LOG.warn("could not obtain gateway signer certificate", e);
            return null;
        }
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
                        // responses. Resolution order:
                        //  1. The CA chain fetched automatically from CEMA
                        //     (GET /ca/{caName}/chain) - no manual truststore needed.
                        //  2. The file-based truststore from auth.truststore.path, if set.
                        //  3. null -> skip certificate-path validation (never return an
                        //     empty list, which breaks PKIX with
                        //     "the trustAnchors parameter must be non-empty").
                        List<X509Certificate> autoChain = getAutomaticallyFetchedCaChain();
                        if (!autoChain.isEmpty()) {
                            LOG.debug("upstream verification: validating protection certificates "
                                    + "against {} automatically fetched CA chain certificate(s)",
                                    autoChain.size());
                            return autoChain;
                        }
                        List<X509Certificate> trusted = getTrustedCertificatesFromTrustStore();
                        if (trusted.isEmpty()) {
                            LOG.debug("upstream verification: no trust anchors available "
                                    + "(automatic CA chain fetch failed/unavailable and no usable "
                                    + "truststore configured), skipping protection-certificate "
                                    + "path validation");
                            return null;
                        }
                        LOG.debug("upstream verification: validating protection certificates "
                                + "against {} trust anchor(s) from the file truststore",
                                trusted.size());
                        return trusted;
                    }

                    @Override
                    public Collection<X509Certificate> getAdditionalCerts() {
                        // The gateway signs its self-generated upstream CertReps with its
                        // own client certificate. When that certificate is not published in
                        // the truststore (e.g. issued by a different CA), supply its issuing
                        // chain here so PKIX path building can still build a valid chain to
                        // a configured trust anchor. Without this, validation fails with
                        // "validating the protection certificate failed" (signerNotTrusted).
                        try {
                            List<X509Certificate> chain = getCertificateChain();
                            if (chain.size() > 1) {
                                // Everything above the leaf acts as intermediate material.
                                LOG.debug("upstream verification: supplying {} additional CA "
                                        + "certificate(s) from the gateway keystore for path "
                                        + "building", chain.size() - 1);
                                return chain.subList(1, chain.size());
                            }
                        } catch (Exception e) {
                            LOG.warn("upstream verification: could not load gateway certificate "
                                    + "chain for additional path-building material", e);
                        }
                        return VerificationContext.super.getAdditionalCerts();
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
