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
import java.util.ArrayList;
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
     * Set while the gateway is generating and protecting an upstream response
     * itself (see CmpGateway.RestUpstream). The RA component runs the full
     * upstream validation chain over that self-generated CertRep, including
     * PKIX path validation of its signature protection against the CA trust
     * anchors. The gateway's signer certificate is normally issued by a
     * different CA (e.g. an admin/RA CA) than the enrollment CA, so that check
     * would fail with "validating the protection certificate failed"
     * (signerNotTrusted). While this flag is set, the gateway keystore chain is
     * merged into the upstream trust anchors - safely, because the validated
     * message originates from our own code, not the network.
     *
     * NOTE: deliberately NOT a ThreadLocal. The RA component re-validates the
     * message returned from the upstream exchange callback AFTER that callback
     * has already completed and its finally-block cleared the flag (observed
     * live as "self-generated response in progress=false" while validating a
     * self-generated CertRep on the same thread pool-1-thread-1). A plain
     * volatile field stays visible for the whole request handling; it is set
     * when the gateway builds a response itself and cleared only after the RA
     * finished validating it (see CmpGateway.sendReceiveMessage wrapper).
     */
    private volatile boolean selfGeneratedUpstreamMessage;

    /** Count of validation queries for diagnosing flag/thread mismatches. */
    private int trustedCertsQueries;

    public boolean isProcessingSelfGeneratedUpstreamMessage() {
        return selfGeneratedUpstreamMessage;
    }

    public void setProcessingSelfGeneratedUpstreamMessage(final boolean processing) {
        this.selfGeneratedUpstreamMessage = processing;
    }

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
        String alias = keyAlias;
        if (alias == null || alias.isEmpty() || !ks.containsAlias(alias)) {
            // No (or a non-matching) auth.keystore.alias configured: pick the first
            // key entry in the keystore instead of failing silently.
            java.util.Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String candidate = aliases.nextElement();
                if (ks.isKeyEntry(candidate)) {
                    if (alias != null && !alias.isEmpty()) {
                        LOG.warn("configured keystore alias '{}' not found; using key entry '{}'",
                                alias, candidate);
                    }
                    alias = candidate;
                    break;
                }
            }
        }
        java.security.cert.Certificate[] certs =
                alias == null ? null : ks.getCertificateChain(alias);
        if (certs == null || certs.length == 0) {
            // The configured key entry stores only the leaf certificate (typical
            // when a PKCS#12 was exported from a keystore without its issuing CA,
            // e.g. the gateway's REST-auth/Tomcat certificate). Without the
            // issuing chain, PKIX path building against this certificate can
            // never succeed. Fall back to any certificate in the keystore whose
            // subject matches the leaf's ISSUER DN - usually the issuing CA
            // stored under its own alias in the same p12 file.
            LOG.warn("keystore entry '{}' has no stored certificate chain beyond"
                            + " the leaf; searching the keystore for the issuing CA",
                    alias);
            List<X509Certificate> rebuilt = rebuildChainFromKeystoreEntries(ks, certs);
            if (rebuilt != null) {
                return rebuilt;
            }
            LOG.warn("issuing CA of the gateway signer certificate not found in"
                    + " the keystore; signature-protected CMP responses signed"
                    + " with it cannot be validated unless the issuing CA is"
                    + " present in auth.truststore.path");
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

    /**
     * Best-effort chain reconstruction: take the leaf (first element of
     * {@code stored}, may be null/empty) and append every keystore certificate
     * whose SUBJECT equals an issuer DN already contained in the partial chain,
     * until nothing matches anymore. Returns the leaf-only list if there is no
     * leaf, or null if no chain beyond the leaf could be built.
     */
    private List<X509Certificate> rebuildChainFromKeystoreEntries(
            final KeyStore ks, final java.security.cert.Certificate[] stored) throws Exception {
        List<X509Certificate> chain = new java.util.ArrayList<>();
        if (stored != null && stored.length > 0 && stored[0] instanceof X509Certificate) {
            chain.add((X509Certificate) stored[0]);
        } else {
            // Not even a leaf on the key alias - pick the single key entry's cert.
            java.util.Enumeration<String> aliases = ks.aliases();
            while (chain.isEmpty() && aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                if (ks.isKeyEntry(a)) {
                    java.security.cert.Certificate c = ks.getCertificate(a);
                    if (c instanceof X509Certificate) {
                        chain.add((X509Certificate) c);
                    }
                }
            }
        }
        if (chain.isEmpty()) {
            return null;
        }
        boolean extended = true;
        while (extended) {
            extended = false;
            String neededIssuer = chain.get(chain.size() - 1).getIssuerX500Principal().getName();
            if (neededIssuer.equals(chain.get(chain.size() - 1).getSubjectX500Principal().getName())) {
                break; // self-signed root reached
            }
            java.util.Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String a = aliases.nextElement();
                java.security.cert.Certificate c = ks.getCertificate(a);
                if (c instanceof X509Certificate) {
                    X509Certificate xc = (X509Certificate) c;
                    if (!chain.contains(xc)
                            && xc.getSubjectX500Principal().getName().equals(neededIssuer)) {
                        chain.add(xc);
                        extended = true;
                        LOG.info("found issuing CA '{}' in keystore entry '{}'; appended to"
                                + " the gateway certificate chain", xc.getSubjectX500Principal(), a);
                        break;
                    }
                }
            }
        }
        return chain.size() > 1 ? chain : null;
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
        // Trust context for validating the ISSUED end-entity certificate.
        // The RA component's downstream stage (RaDownstream.processCertResponse)
        // runs validateCertAgainstTrust(issued cert, extraCerts of the response)
        // and aborts with "could not validate trust chain of issued certificate"
        // if that returns null/empty - which it did when we returned null here
        // (in this RA version null anchors are a hard failure, not a skip).
        // Correct behaviour for a gateway: trust exactly the issuing CA(s) of the
        // CMP template in use - the chain fetched from CEMA via GET /ca/{caName}/chain.
        return new VerificationContext() {
            @Override
            public Collection<X509Certificate> getTrustedCertificates() {
                List<X509Certificate> caChain = getAutomaticallyFetchedCaChain();
                LOG.info("enrollment verification: validating issued certificate against "
                                + "{} trust anchor(s): {}",
                        caChain.size(),
                        caChain.stream()
                                .map(c -> c.getSubjectX500Principal().getName())
                                .collect(java.util.stream.Collectors.toList()));
                return caChain.isEmpty() ? null : caChain;
            }

            @Override
            public Collection<X509Certificate> getAdditionalCerts() {
                // Path-building material: the CA chain itself acts as intermediate
                // source (e.g. EE <- CEMA User CA <- CEMA Root CA anchor).
                List<X509Certificate> caChain = getAutomaticallyFetchedCaChain();
                return caChain.isEmpty() ? null : caChain;
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
                        // NOTE: returning null does NOT skip validation in this RA
                        // component version - TrustCredentialAdapter.validateCertAgainstTrust
                        // treats null trust anchors as a hard failure ("validating the
                        // protection certificate failed"). So instead of skipping, always
                        // supply the broadest usable anchor set. Responses generated by the
                        // gateway itself are protected either with the gateway's own client
                        // certificate or with the echoed EE signer certificate - neither can
                        // build a PKIX path to the enrollment CA chain alone (see
                        // selfGeneratedUpstreamMessage). Merge the gateway keystore chain and
                        // the file truststore into the anchors so every legitimate signer has
                        // a path.
                        // Trust anchors for validating signature-protected upstream
                        // responses. Resolution order:
                        //  1. Union of: CA chain fetched automatically from CEMA
                        //     (GET /ca/{caName}/chain), the gateway keystore certificate
                        //     chain, and the file-based truststore (auth.truststore.path).
                        //  2. null only if nothing at all is available -> that makes the
                        //     RA reject signed responses; never return an empty list, which
                        //     breaks PKIX with "the trustAnchors parameter must be
                        //     non-empty".
                        java.util.Set<List<X509Certificate>> anchorSources = new java.util.LinkedHashSet<>();
                        anchorSources.add(getAutomaticallyFetchedCaChain());
                        // INFO on purpose: if this ever shows selfGenerated=false while the
                        // gateway is answering a signature-protected request, the merge
                        // below is skipped and the RA rejects with "validating the
                        // protection certificate failed" (thread-boundary problem).
                        LOG.info("upstream trust anchor query #{}: self-generated response in "
                                        + "progress={} (thread {})",
                                ++trustedCertsQueries,
                                isProcessingSelfGeneratedUpstreamMessage(),
                                Thread.currentThread().getName());
                        if (isProcessingSelfGeneratedUpstreamMessage()) {
                            try {
                                List<X509Certificate> keystoreChain = getCertificateChain();
                                LOG.info("merging gateway keystore chain into trust anchors: {}",
                                        keystoreChain == null ? "not available"
                                                : keystoreChain.stream()
                                                        .map(c -> c.getSubjectX500Principal().getName())
                                                        .collect(java.util.stream.Collectors.toList()));
                                anchorSources.add(keystoreChain);
                            } catch (Exception e) {
                                LOG.warn("upstream verification: could not load gateway keystore "
                                        + "certificate chain as trust anchors", e);
                            }
                        }
                        anchorSources.add(getTrustedCertificatesFromTrustStore());
                        List<X509Certificate> trusted = new ArrayList<>();
                        java.util.Set<java.security.cert.X509Certificate> seen = new java.util.HashSet<>();
                        for (List<X509Certificate> source : anchorSources) {
                            if (source == null) {
                                continue;
                            }
                            for (X509Certificate c : source) {
                                if (c != null && seen.add(c)) {
                                    trusted.add(c);
                                }
                            }
                        }
                        if (isProcessingSelfGeneratedUpstreamMessage()) {
                            LOG.debug("upstream verification: self-generated response - merged "
                                    + "{} trust anchor(s) (CA chain + gateway keystore chain + "
                                    + "truststore)", trusted.size());
                        }
                        if (!trusted.isEmpty()) {
                            LOG.info("upstream verification: validating protection certificate "
                                    + "against {} trust anchor(s): {}",
                                    trusted.size(),
                                    trusted.stream()
                                            .map(c -> c.getSubjectX500Principal().getName())
                                            .collect(java.util.stream.Collectors.toList()));
                            return trusted;
                        }
                        LOG.debug("upstream verification: no trust anchors available "
                                + "(automatic CA chain fetch failed/unavailable and no usable "
                                + "truststore configured); signature-protected upstream "
                                + "responses will be rejected");
                        return null;
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
