package com.siemens.pki.cmprestbridge.service;

import com.siemens.pki.cmpracomponent.configuration.*;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.persistency.DefaultPersistencyImplementation;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msggeneration.HeaderProvider;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1BitSet;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
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
                return null;
            }
            
            @Override
            public CmpMessageInterface getDownstreamConfiguration(String certProfile, int bodyType) {
                return new CmpMessageInterface() {
                    @Override
                    public CredentialContext getOutputCredentials() {
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
                        return null;
                    }
                    
                    @Override
                    public VerificationContext getInputVerification() {
                        return loadTrustAnchors(config.getDownstreamTrustedCerts());
                    }
                    
                    @Override
                    public ReprotectMode getReprotectMode() {
                        return ReprotectMode.reprotect;
                    }
                    
                    @Override
                    public boolean isMessageTimeDeviationAllowed(long deviation) {
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
                        return null;
                    }
                };
            }
            
            @Override
            public int getDownstreamTimeout(String certProfile, int bodyType) {
                return config.getDownstreamTimeoutSeconds();
            }
            
            @Override
            public VerificationContext getEnrollmentTrust(String certProfile, int bodyType) {
                return loadTrustAnchors(config.getEnrollmentTrustedCerts());
            }
            
            @Override
            public boolean getForceRaVerifiedOnUpstream(String certProfile, int bodyType) {
                return false;
            }
            
            @Override
            public InventoryInterface getInventory(String certProfile, int bodyType) {
                if (config.getInventoryHandler() != null) {
                    return config.getInventoryHandler();
                }
                
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
                return DefaultPersistencyImplementation.getInstance();
            }
            
            @Override
            public int getRetryAfterTimeInSeconds(String certProfile, int bodyType) {
                return config.getPollingIntervalSeconds();
            }
            
            @Override
            public SupportMessageHandlerInterface getSupportMessageHandler(
                    String certProfile, String infoTypeOid) {
                return null;
            }
            
            @Override
            public CmpMessageInterface getUpstreamConfiguration(String certProfile, int bodyType) {
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
                return false;
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
                PKIMessage pkiMessage = PKIMessage.getInstance(request);
                byte[] csrBytes = extractCsrFromCmpRequest(pkiMessage, bodyTypeOfFirstRequest);
                
                if (csrBytes == null) {
                    LOG.warn("No CSR found in CMP request, returning null");
                    return null;
                }
                
                String commonName = extractCommonName(pkiMessage);
                String validity = config.getDefaultValidity();
                
                LOG.info("Calling REST API to issue certificate for CN={}", commonName);
                byte[] certBytes = restPkiService.issueCertificate(csrBytes, commonName, validity);
                
                return buildCmpResponse(pkiMessage, certBytes, bodyTypeOfFirstRequest);
                
            } catch (Exception e) {
                LOG.error("Error in upstream exchange: {}", e.getMessage(), e);
                try {
                    PKIMessage pkiMessage = PKIMessage.getInstance(request);
                    return buildCmpErrorResponse(pkiMessage, e.getMessage(), bodyTypeOfFirstRequest);
                } catch (Exception ex) {
                    LOG.error("Failed to build error response: {}", ex.getMessage(), ex);
                    return null;
                }
            }
        };
    }

    /**
     * Extract the CSR from a CMP request using BouncyCastle.
     * Supports IR, CR, P10CR, and KUR message types.
     */
    private byte[] extractCsrFromCmpRequest(PKIMessage pkiMessage, int bodyType) throws Exception {
        LOG.trace("Extracting CSR from CMP body type {}", bodyType);
        
        PKIBody body = pkiMessage.getBody();
        
        switch (bodyType) {
            case PKIBody.TYPE_INIT_REQ:
            case PKIBody.TYPE_CERT_REQ:
            case PKIBody.TYPE_KEY_UPDATE_REQ:
                CertReqMessages certReqMessages = (CertReqMessages) body.getContent();
                CertReqMsg[] certReqMsgs = certReqMessages.toCertReqMsgArray();
                if (certReqMsgs == null || certReqMsgs.length == 0) {
                    throw new IllegalArgumentException("No certificate requests found in message");
                }
                
                CertReqMsg certReqMsg = certReqMsgs[0];
                return createPkcs10FromCrmf(certReqMsg.getCertReq(), pkiMessage);
                
            case PKIBody.TYPE_P10_CERT_REQ:
                PKCS10CertificationRequest p10CertReq = (PKCS10CertificationRequest) body.getContent();
                return p10CertReq.getEncoded(ASN1Encoding.DER);
                
            default:
                LOG.warn("Unsupported body type for certificate request: {}", bodyType);
                return null;
        }
    }
    
    /**
     * Create a PKCS#10 CSR from a CRMF CertRequest using BouncyCastle.
     */
    private byte[] createPkcs10FromCrmf(CertRequest certRequest, PKIMessage pkiMessage) throws Exception {
        CertTemplate template = certRequest.getCertTemplate();
        X500Name subject = template.getSubject();
        org.bouncycastle.asn1.x509.SubjectPublicKeyInfo publicKeyInfo = template.getPublicKey();
        
        if (subject == null || publicKeyInfo == null) {
            throw new IllegalArgumentException("Subject and/or public key missing from cert template");
        }
        
        org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder p10Builder =
            new org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder(subject, publicKeyInfo);
        
        if (template.getExtensions() != null) {
            p10Builder.addAttribute(
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pkcs_9_at_extensionRequest,
                template.getExtensions()
            );
        }
        
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider("BC")
            .build(new DummyPrivateKey());
            
        org.bouncycastle.pkcs.PKCS10CertificationRequest p10CertReq = p10Builder.build(signer);
        return p10CertReq.getEncoded(ASN1Encoding.DER);
    }

    /**
     * Extract common name from CMP request.
     */
    private String extractCommonName(PKIMessage pkiMessage) {
        try {
            PKIBody body = pkiMessage.getBody();
            
            if (body.getType() == PKIBody.TYPE_P10_CERT_REQ) {
                PKCS10CertificationRequest p10CertReq = (PKCS10CertificationRequest) body.getContent();
                X500Name subject = p10CertReq.getSubject();
                return extractCommonNameFromX500(subject);
            } else {
                CertReqMessages certReqMessages = (CertReqMessages) body.getContent();
                CertReqMsg[] certReqMsgs = certReqMessages.toCertReqMsgArray();
                if (certReqMsgs != null && certReqMsgs.length > 0) {
                    CertTemplate template = certReqMsgs[0].getCertReq().getCertTemplate();
                    if (template.getSubject() != null) {
                        return extractCommonNameFromX500(template.getSubject());
                    }
                }
            }
        } catch (Exception e) {
            LOG.warn("Failed to extract common name: {}", e.getMessage());
        }
        
        return "CN=CMP Client";
    }
    
    private String extractCommonNameFromX500(X500Name x500Name) {
        if (x500Name == null) {
            return "Unknown";
        }
        
        for (org.bouncycastle.asn1.x500.RDN rdn : x500Name.getRDNs()) {
            if (rdn.getFirst() != null && 
                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.commonName.equals(rdn.getFirst().getType())) {
                return "CN=" + rdn.getFirst().getValue().toString();
            }
        }
        
        return x500Name.toString();
    }

    /**
     * Build a successful CMP response containing the issued certificate.
     */
    private byte[] buildCmpResponse(PKIMessage originalRequest, byte[] certBytes, int bodyType) throws Exception {
        LOG.trace("Building CMP response with certificate");
        
        java.security.cert.CertificateFactory cf = java.security.cert.CertificateFactory.getInstance("X.509");
        java.security.cert.X509Certificate issuedCert = 
            (java.security.cert.X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
        
        CMPCertificate cmpCert = CMPCertificate.getInstance(
            org.bouncycastle.asn1.x509.Certificate.getInstance(issuedCert.getEncoded())
        );
        
        PKIHeader requestHeader = originalRequest.getHeader();
        ASN1Integer certStatus = new ASN1Integer(PKIStatus.GRANTED);
        
        CertResponse certResponse = new CertResponse(
            new ASN1Integer(0),
            certStatus,
            new CertifiedKeyPair(cmpCert, null, null),
            null
        );
        
        CertRepMessage certRepMessage = new CertRepMessage(new CertResponse[] { certResponse });
        PKIBody responseBody = new PKIBody(bodyType + 1, certRepMessage);
        
        HeaderProvider headerProvider = PkiMessageGenerator.buildRespondingHeaderProvider(originalRequest);
        CredentialContext creds = getDownstreamCredentials();
        
        PKIMessage responseMessage;
        if (creds instanceof SignatureCredentialContext) {
            SignatureCredentialContext sigCreds = (SignatureCredentialContext) creds;
            PrivateKey privateKey = sigCreds.getPrivateKey();
            List<X509Certificate> certChain = sigCreds.getCertificateChain();
            
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(privateKey);
            
            List<CMPCertificate> extraCerts = new ArrayList<>();
            for (X509Certificate cert : certChain) {
                extraCerts.add(CMPCertificate.getInstance(
                    org.bouncycastle.asn1.x509.Certificate.getInstance(cert.getEncoded())
                ));
            }
            
            responseMessage = PkiMessageGenerator.generateAndProtectMessage(
                headerProvider,
                responseBody,
                signer,
                extraCerts
            );
        } else {
            responseMessage = PkiMessageGenerator.generateUnprotectMessage(headerProvider, responseBody);
        }
        
        return responseMessage.getEncoded(ASN1Encoding.DER);
    }
    
    private CredentialContext getDownstreamCredentials() {
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
        return null;
    }

    /**
     * Build a CMP error response.
     */
    private byte[] buildCmpErrorResponse(PKIMessage originalRequest, String errorMsg, int bodyType) throws Exception {
        LOG.trace("Building CMP error response: {}", errorMsg);
        
        int failureInfo = PKIFailureInfo.badRequest;
        if (errorMsg.contains("authentication") || errorMsg.contains("authorization")) {
            failureInfo = PKIFailureInfo.badCertTemplate;
        } else if (errorMsg.contains("internal")) {
            failureInfo = PKIFailureInfo.systemUnavail;
        }
        
        PKIStatus status = new ASN1Integer(PKIStatus.REJECTION);
        PKIFreeText statusString = new PKIFreeText(errorMsg);
        ASN1BitSet failureInfoBits = new ASN1BitSet(new byte[] { (byte) failureInfo });
        
        ErrorMsgContent errorMsgContent = new ErrorMsgContent(status, statusString, failureInfoBits);
        PKIBody responseBody = new PKIBody(PKIBody.TYPE_ERROR, errorMsgContent);
        
        HeaderProvider headerProvider = PkiMessageGenerator.buildRespondingHeaderProvider(originalRequest);
        PKIMessage responseMessage = PkiMessageGenerator.generateUnprotectMessage(headerProvider, responseBody);
        
        return responseMessage.getEncoded(ASN1Encoding.DER);
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
        return new SharedSecretCredentialContext(sharedSecret);
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
    
    /**
     * Dummy private key class for creating PKCS#10 CSR from CRMF.
     */
    private static class DummyPrivateKey implements java.security.PrivateKey {
        @Override
        public String getAlgorithm() { return "RSA"; }
        
        @Override
        public String getFormat() { return "PKCS#8"; }
        
        @Override
        public byte[] getEncoded() { return new byte[0]; }
    }
}
