/*
 *  Copyright (c) 2024 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 */
package com.siemens.pki.cmpgateway.server;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.NestedEndpointContext;
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.SignatureCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.cryptoservices.CertUtility;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.msggeneration.MsgOutputProtector;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msgprocessing.StreamType;
import com.siemens.pki.cmpracomponent.msgvalidation.BaseCmpException;
import com.siemens.pki.cmpracomponent.msgvalidation.CmpValidationException;
import com.siemens.pki.cmpracomponent.msgvalidation.InputValidator;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageContext;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageHeaderValidator;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.protection.OutputSharedSecretCredentials;
import com.siemens.pki.cmpgateway.config.GatewayConfig;
import com.siemens.pki.cmpgateway.rest.RestClient;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.ProtectedPart;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cmp.RevDetails;
import org.bouncycastle.asn1.cmp.RevRepContentBuilder;
import org.bouncycastle.asn1.cmp.RevReqContent;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP adapter around cmp-ra-component. CEMA is deliberately not modified.
 *
 * <p>The RA component owns CMP parsing, protection, transaction state, polling,
 * and response protection. This class only maps the operations that CEMA's
 * current REST API can actually represent.</p>
 */
public final class CmpGateway {

    private static final Logger LOG = LoggerFactory.getLogger(CmpGateway.class);
    private static final int CMP_PORT = 9000;
    private static final String CMP_PATH = "/cmp";

    private final GatewayConfig config;
    private final RestClient restClient;
    private final CmpRaInterface cmpRaInterface;
    private final HttpServer httpServer;
    private final ExecutorService executor = Executors.newFixedThreadPool(10);

    public CmpGateway(final GatewayConfig config) throws Exception {
        this.config = config;
        this.restClient = new RestClient(
                config.getRestBaseUrl(),
                config.getCaName(),
                config.getTplName(),
                config.getLookupName(),
                config.getAuthType(),
                config.getUsername(),
                config.getPassword(),
                config.loadKeyStore(),
                config.getKeystorePassword(),
                config.getKeyAlias(),
                config.loadTrustStore());
        // Automatic trust anchors for CMP protection validation: fetch the CA chain
        // from CEMA itself (GET /ca/{caName}/chain) instead of requiring a manually
        // exported truststore file. Fetched lazily on first use and cached; if it
        // fails, GatewayConfig falls back to auth.truststore.path or skips path
        // validation (with a log message).
        config.setUpstreamTrustSupplier(() -> {
            try {
                return restClient.fetchCaChain(config.getCaName());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("Interrupted while fetching the CA chain", e);
            } catch (IOException e) {
                throw new IllegalStateException("Could not fetch the CA chain from CEMA", e);
            }
        });
        this.cmpRaInterface = CmpRaComponent.instantiateCmpRaComponent(config, new RestUpstream());
        this.httpServer = HttpServer.create(new InetSocketAddress(config.getCmpPort()), 0);
        httpServer.createContext(config.getCmpPath(), new CmpHandler());
        httpServer.setExecutor(executor);
    }

    private final class RestUpstream implements UpstreamExchange, CmpRaComponent.GeneratedKeyProvider {

        private static final String UPSTREAM_INTERFACE_NAME = "CMP upstream";

        /**
         * Tracks the transaction state of the request currently being processed
         * by {@link #sendReceiveMessage(byte[], String, int)}, which is invoked
         * synchronously while the RA component handles the downstream request.
         */
        private final ThreadLocal<PersistencyContext> currentTransaction = new ThreadLocal<>();

        private final Map<String, PrivateKey> generatedKeys = new ConcurrentHashMap<>();
        private final Map<String, Boolean> centralKeyRequests = new ConcurrentHashMap<>();

        @Override
        public void markCentralKeyGeneration(final byte[] transactionId) {
            centralKeyRequests.put(Base64.getEncoder().encodeToString(transactionId), Boolean.TRUE);
        }

        @Override
        public PrivateKey getGeneratedPrivateKey(final byte[] transactionId) {
            return generatedKeys.remove(Base64.getEncoder().encodeToString(transactionId));
        }

        @Override
        public byte[] sendReceiveMessage(
                final byte[] request, final String certProfile, final int bodyType) throws Exception {
            final PKIMessage message = parseMessage(request);
            if (LOG.isDebugEnabled()) {
                LOG.debug("upstream request received by gateway callback: LCMP body type {}, senderNID='{}', "
                                + "protection algorithm '{}', extraCerts count {}",
                        bodyType,
                        message.getHeader().getSender() == null
                                ? null : message.getHeader().getSender().getName(),
                        message.getHeader().getProtectionAlg() == null
                                ? "none" : message.getHeader().getProtectionAlg().getAlgorithm().getId(),
                        message.getExtraCerts() == null ? 0 : message.getExtraCerts().length);
            }
            // Remember the transaction of the request being processed so that the
            // generated upstream responses can be protected with the matching
            // credentials (see protectUpstreamResponse).
            final PersistencyContext persistencyContext = new PersistencyContext();
            persistencyContext.setRequestType(bodyType);
            currentTransaction.set(persistencyContext);
            // Everything returned from this callback is generated by the gateway
            // itself and protected with the gateway signer certificate, which is
            // typically not issued by the enrollment CA. Tell GatewayConfig to skip
            // PKIX path validation of that self-generated protection certificate
            // (see selfGeneratedUpstreamMessage) - otherwise the RA component would
            // reject its own responses with "validating the protection certificate
            // failed" (signerNotTrusted).
            config.setProcessingSelfGeneratedUpstreamMessage(true);
            try {
                switch (bodyType) {
                    case PKIBody.TYPE_P10_CERT_REQ:
                        return issuePkcs10(message, certProfile, persistencyContext);
                    case PKIBody.TYPE_REVOCATION_REQ:
                        return revoke(message);
                    case PKIBody.TYPE_INIT_REQ:
                    case PKIBody.TYPE_CERT_REQ:
                    case PKIBody.TYPE_KEY_UPDATE_REQ:
                        if (!config.isCrmfEnabled()) {
                            // The CEMA REST API supports CSR (PKCS#10) enrollment only.
                            // Reject CRMF with a readable error instead of failing later
                            // in the upstream protection/validation chain.
                            return errorMessage(message, bodyType,
                                    "CRMF is not supported by this gateway; the CEMA backend"
                                            + " accepts PKCS#10 (CSR) requests only."
                                            + " Use a P10CR client transaction (e.g."
                                            + " EnrollmentType: P10CR in the LCMP client config).");
                        }
                        return processCrmf(message, certProfile, persistencyContext);
                    case PKIBody.TYPE_GEN_MSG:
                        return handleGeneralMessage(message, certProfile, persistencyContext);
                    default:
                        throw new UnsupportedOperationException(
                                "LCMP body type " + bodyType + " is not mapped to CEMA");
                }
            } finally {
                config.setProcessingSelfGeneratedUpstreamMessage(false);
                currentTransaction.remove();
            }
        }

        /**
         * Build a CMP error response (PKIResponse with status rejection) for the
         * given request. Used to reject message types the CEMA backend cannot
         * handle (e.g. CRMF when only CSR issuance is available) with a readable
         * statusInfo instead of an opaque transport-level ERROR.
         */
        private byte[] errorMessage(
                final PKIMessage request, final int requestBodyType, final String text)
                throws Exception {
            final int responseType;
            switch (requestBodyType) {
                case PKIBody.TYPE_INIT_REQ:
                    responseType = PKIBody.TYPE_INIT_REP;
                    break;
                case PKIBody.TYPE_CERT_REQ:
                    responseType = PKIBody.TYPE_CERT_REP;
                    break;
                case PKIBody.TYPE_KEY_UPDATE_REQ:
                    responseType = PKIBody.TYPE_KEY_UPDATE_REP;
                    break;
                default:
                    responseType = PKIBody.TYPE_ERROR;
            }
            LOG.warn("rejecting CMP request: {}", text);
            final org.bouncycastle.asn1.cmp.PKIFreeText freeText =
                    new org.bouncycastle.asn1.cmp.PKIFreeText(text);
            final PKIBody responseBody;
            if (responseType == PKIBody.TYPE_ERROR) {
                responseBody = new PKIBody(
                        responseType,
                        new org.bouncycastle.asn1.cmp.PKIStatusInfo(
                                PKIStatus.rejection, freeText, null));
            } else {
                final CertResponse rejected = new CertResponse(
                        new ASN1Integer(BigInteger.ZERO),
                        new PKIStatusInfo(
                                PKIStatus.rejection,
                                freeText,
                                null));
                responseBody = new PKIBody(
                        responseType, new CertRepMessage(null, new CertResponse[] {rejected}));
            }
            return PkiMessageGenerator.generateUnprotectMessage(
                            PkiMessageGenerator.buildRespondingHeaderProvider(request), responseBody)
                    .getEncoded();
        }

        private byte[] processCrmf(
                final PKIMessage request, final String certProfile,
                final PersistencyContext persistencyContext) throws Exception {
            CertReqMsg[] requests = CertReqMessages.getInstance(request.getBody().getContent())
                        .toCertReqMsgArray();
            if (requests.length != 1) {
                throw new UnsupportedOperationException(
                            "batched CRMF processing is not implemented by the CEMA adapter");
            }
            CertReqMsg certReqMsg = requests[0];
            CertRequest certRequest = certReqMsg.getCertReq();
            CertTemplate template = certRequest.getCertTemplate();
            final String transactionKey =
                    Base64.getEncoder().encodeToString(request.getHeader().getTransactionID().getOctets());
            if (!Boolean.TRUE.equals(centralKeyRequests.remove(transactionKey))
                    && !isCentralKeyGenerationRequest(template)) {
                // Ordinary CRMF with a client-supplied public key: CEMA has no
                // endpoint for it yet, so fail directly here.
                throw new UnsupportedOperationException(
                        "ordinary CRMF issuance (with subject public key) is not representable by the "
                                + "available CEMA REST API");
            }
            return generateCentralKey(request, certReqMsg, persistencyContext);
        }

        private boolean isCentralKeyGenerationRequest(final CertTemplate template) {
            if (template.getPublicKey() == null || template.getPublicKey().getPublicKeyData() == null) {
                return true;
            }
            final byte[] publicKeyData = template.getPublicKey().getPublicKeyData().getOctets();
            if (publicKeyData.length <= 1) {
                return true;
            }
            for (byte value : publicKeyData) {
                if (value != 0) {
                    return false;
                }
            }
            return true;
        }

        private byte[] generateCentralKey(
                final PKIMessage request, final CertReqMsg certReqMsg,
                final PersistencyContext persistencyContext) throws Exception {
            String commonName = null;
            final String transactionKey =
                    Base64.getEncoder().encodeToString(request.getHeader().getTransactionID().getOctets());
            CertTemplate template = certReqMsg.getCertReq().getCertTemplate();
            if (template.getSubject() != null) {
                // CertTemplate.getSubject() returns the generic ASN1Encodable of the CHOICE
                // (Name / RDNSequence); it must be narrowed to X500Name before its RDNs can be
                // enumerated as an array.
                final X500Name subject = X500Name.getInstance(template.getSubject());
                final RDN[] commonNames = subject.getRDNs(BCStyle.CN);
                if (commonNames.length > 0) {
                    final AttributeTypeAndValue firstCn = commonNames[0].getFirst();
                    if (firstCn != null && firstCn.getValue() != null) {
                        // getValue() returns ASN1Encodable; toString() gives the string form of
                        // the CN value (e.g. DERUTF8String -> its text content).
                        commonName = firstCn.getValue().toString();
                    }
                }
            }
            RestClient.CertificateResult result = awaitResult(
                        restClient.generateCertificate(
                                config.getCentralKeyKind(),
                                config.getCentralKeySize(),
                                config.getCentralKeyCurve(),
                                commonName));
            byte[] certificate = result.certificate;
            if (certificate == null || result.privateKey == null) {
                throw new IOException("CEMA generate response did not contain certificate and private key");
            }
            generatedKeys.put(transactionKey, parsePrivateKey(result.privateKey));
            return certificateResponse(
                    request,
                    persistencyContext,
                    certReqMsg.getCertReq().getCertReqId().getValue(),
                    certificate);
        }

        private PrivateKey parsePrivateKey(final byte[] encoded) throws Exception {
            Exception last = null;
            for (String algorithm : new String[] {"RSA", "EC", "Ed25519", "Ed448"}) {
                try {
                    return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(encoded));
                } catch (Exception exception) {
                    last = exception;
                }
            }
            throw new IOException("CEMA returned an unsupported private-key encoding", last);
        }
        private byte[] issuePkcs10(
                final PKIMessage request, final String certProfile,
                final PersistencyContext persistencyContext) throws Exception {
            final CertificationRequest csr =
                    CertificationRequest.getInstance(request.getBody().getContent());
            // If no lookup is configured (or it is blank or the unused default), use the direct
            // template-based endpoint /ca/{caName}/template/{tplName}/issue instead of auto-issue.
            final String lookup = config.getLookupName();
            final boolean useLookup = lookup != null && !lookup.isBlank() && !"default".equals(lookup);
            final RestClient.CertificateResult result = useLookup
                    ? restClient.autoIssueCertificate(Base64.getEncoder().encodeToString(csr.getEncoded()))
                    : restClient.issueCertificate(Base64.getEncoder().encodeToString(csr.getEncoded()));
            return certificateResponse(request, persistencyContext, BigInteger.ZERO, awaitCertificate(result));
        }

        private byte[] awaitCertificate(final RestClient.CertificateResult initial) throws Exception {
            return awaitResult(initial).certificate;
        }

        private RestClient.CertificateResult awaitResult(final RestClient.CertificateResult initial)
                throws Exception {
            RestClient.CertificateResult result = initial;
            final long deadline = System.currentTimeMillis()
                    + config.getDownstreamTimeoutSeconds() * 1000L;
            while (result.pending && System.currentTimeMillis() < deadline) {
                Thread.sleep(Math.max(1000L, config.getRetryAfterSeconds() * 1000L));
                result = restClient.fetchPendingCertificate(result.uuid);
            }
            if (result.pending) {
                throw new IOException("CEMA certificate issuance did not complete before the gateway timeout");
            }
            return result;
        }

        /**
         * Handle an LCMP General Message (GenMsg, RFC 4210 section 5.2.3).
         *
         * <p>The CEMA backend has no CMP general-message endpoint, so the gateway
         * answers the informational requests it can serve locally:</p>
         * <ul>
         *   <li>{@code id-it-certTemplates} (1.3.6.1.5.5.7.48.1.9): returns the
         *       configured CA name and certificate template as a free-text infoVal -
         *       a simple way to check that the gateway round-trip works.</li>
         *   <li>{@code id-it-caProtEncCert} (1.3.6.1.5.5.7.48.1.2): returns the
         *       gateway's own signer certificate if it is available from the
         *       keystore configuration.</li>
         *   <li>Anything else: rejected with a readable status text instead of a
         *       transport-level error, so clients see a proper GenRep.</li>
         * </ul>
         */
        private byte[] handleGeneralMessage(
                final PKIMessage request, final String certProfile,
                final PersistencyContext persistencyContext) throws Exception {
            final GenMsgContent genMsg = GenMsgContent.getInstance(request.getBody().getContent());
            final InfoTypeAndValue[] requests = genMsg.toInfoTypeAndValueArray();
            if (requests.length == 0) {
                throw new IllegalArgumentException("GenMsg contains no infoTypeAndValues");
            }
            final java.util.List<InfoTypeAndValue> responses = new java.util.ArrayList<>();
            for (InfoTypeAndValue info : requests) {
                final String oid = info.getInfoType().getId();
                switch (oid) {
                    case "1.3.6.1.5.5.7.48.1.9": // id-it-certTemplates
                        responses.add(new InfoTypeAndValue(
                                info.getInfoType(),
                                new org.bouncycastle.asn1.DERUTF8String(
                                        "CA=" + config.getCaName()
                                                + ",template=" + config.getTplName())));
                        break;
                    case "1.3.6.1.5.5.7.48.1.2": { // id-it-caProtEncCert
                        org.bouncycastle.asn1.x509.Certificate signer =
                                config.getSignerCertificateOrNull();
                        if (signer == null) {
                            responses.add(rejectedInfo(info,
                                    "no gateway protection certificate is configured"));
                        } else {
                            responses.add(new InfoTypeAndValue(
                                    info.getInfoType(),
                                    new CMPCertificate(signer)));
                        }
                        break;
                    }
                    default:
                        responses.add(rejectedInfo(info,
                                "general message topic " + oid + " is not served by this gateway"));
                        break;
                }
            }
            LOG.info("answered GenMsg with {} infoTypeAndValue response(s)", responses.size());
            final PKIBody responseBody = new PKIBody(
                    PKIBody.TYPE_GEN_REP,
                    new GenRepContent(responses.toArray(new InfoTypeAndValue[0])));
            return protectUpstreamResponse(request, persistencyContext, responseBody).getEncoded();
        }

        private static InfoTypeAndValue rejectedInfo(
                final InfoTypeAndValue request, final String text) {
            return new InfoTypeAndValue(
                    request.getInfoType(),
                    new org.bouncycastle.asn1.cmp.PKIStatusInfo(
                            PKIStatus.rejection,
                            new org.bouncycastle.asn1.cmp.PKIFreeText(text),
                            null));
        }

        private byte[] revoke(final PKIMessage request) throws Exception {
            final RevReqContent content = RevReqContent.getInstance(request.getBody().getContent());
            final RevDetails[] revDetails = content.toRevDetailsArray();
            if (revDetails.length == 0
                    || revDetails[0].getCertDetails().getSerialNumber() == null) {
                throw new IllegalArgumentException("revocation request does not contain a certificate serial number");
            }
            final BigInteger serial =
                    revDetails[0].getCertDetails().getSerialNumber().getValue();
            restClient.revokeCertificate(serial.toString(), extractReasonCode(revDetails[0]));
            // RevRepContent is explicitly allowed to be unprotected per RFC 4210 /
            // RFC 9483, and the RA component's upstream ProtectionValidator accepts
            // an unprotected REVOCATION_REP - so no protection is added here.
            final PKIBody responseBody = new PKIBody(
                    PKIBody.TYPE_REVOCATION_REP,
                    new RevRepContentBuilder().add(new PKIStatusInfo(PKIStatus.granted)).build());
            return PkiMessageGenerator.generateUnprotectMessage(
                            PkiMessageGenerator.buildRespondingHeaderProvider(request), responseBody)
                    .getEncoded();
        }

        /**
         * Extract the CRL reason code (RFC 5280 {@code reasonCode} extension inside
         * {@code RevDetails.crlEntryDetails}) from a CMP revocation request. Returns
         * 0 (unspecified) when the client did not supply the extension; values are
         * clamped to the legal 0..10 range (the RA component's MessageBodyValidator
         * rejects out-of-range codes before this point, this is just defensive).
         */
        private static int extractReasonCode(final RevDetails revDetails) {
            final Extensions crlEntryDetails = revDetails.getCrlEntryDetails();
            if (crlEntryDetails == null) {
                return 0;
            }
            final Extension reasonCodeExt = crlEntryDetails.getExtension(Extension.reasonCode);
            if (reasonCodeExt == null) {
                return 0;
            }
            final long reasonCode = org.bouncycastle.asn1.ASN1Enumerated
                    .getInstance(reasonCodeExt.getParsedValue())
                    .getValue()
                    .longValue();
            return (int) Math.min(Math.max(reasonCode, 0L), 10L);
        }

        private byte[] certificateResponse(
                final PKIMessage request,
                final PersistencyContext persistencyContext,
                final BigInteger certReqId,
                final byte[] encodedCertificate)
                throws Exception {
            final Certificate certificate = Certificate.getInstance(
                    ASN1Primitive.fromByteArray(encodedCertificate));
            final CMPCertificate cmpCertificate = new CMPCertificate(certificate);
            final CertResponse response = new CertResponse(
                    new ASN1Integer(certReqId),
                    new PKIStatusInfo(PKIStatus.granted),
                    new org.bouncycastle.asn1.cmp.CertifiedKeyPair(new CertOrEncCert(cmpCertificate)),
                    null);
            final int responseType = request.getBody().getType() == PKIBody.TYPE_P10_CERT_REQ
                    ? PKIBody.TYPE_CERT_REP
                    : request.getBody().getType() + 1;
            final PKIBody responseBody = new PKIBody(
                    responseType, new CertRepMessage(null, new CertResponse[] {response}));
            return protectUpstreamResponse(request, persistencyContext, responseBody).getEncoded();
        }

        /**
         * Protect an upstream (RA-side) response with the same credentials that
         * were used to protect the related downstream request.
         *
         * <p>The RA component validates every message coming back from the
         * upstream exchange through
         * {@link com.siemens.pki.cmpracomponent.msgvalidation.ProtectionValidator}
         * using {@code Configuration.getUpstreamConfiguration()}. Since CEMA is
         * driven over plain REST and returns unprotected CMP structures, the
         * gateway must add protection itself before handing the response back to
         * the RA component; otherwise validation fails with
         * "message is incomplete protected but protection is required".</p>
         *
         * <p>Credential selection mirrors what a real CMP server does when it
         * answers a request: the response is protected with the <em>same</em>
         * algorithm and credentials that protected the request.</p>
         * <ul>
         *   <li>PasswordBasedMac request: recompute the PBM key material
         *       directly from the request header (salt, OWF iteration count,
         *       MAC algorithm) plus the configured shared secret and answer
         *       with an identical PBM protection. This deliberately bypasses
         *       {@link InputValidator}: validating the downstream request here
         *       would run the full body validation chain (including CRMF
         *       controls and enrollment trust), which is neither needed nor
         *       safe inside the upstream callback.</li>
         *   <li>PBMAC1 request: PBMAC1 parameters are per-message salted and
         *       cannot be recomputed from the shared secret alone; fall back to
         *       the configured upstream output credentials.</li>
         *   <li>Signature-protected request: echo the senderKID and answer with
         *       the configured upstream output credentials (the gateway
         *       certificate).</li>
         * </ul>
         */
        private PKIMessage protectUpstreamResponse(
                final PKIMessage request,
                final PersistencyContext persistencyContext,
                final PKIBody responseBody)
                throws Exception {
            final CmpMessageInterface upstreamConfig = config.getUpstreamConfiguration(
                    persistencyContext.getCertProfile(), responseBody.getType());
            if (LOG.isDebugEnabled()) {
                LOG.debug("protecting generated upstream response (body type {}); incoming request is "
                                + "protected with {}",
                        responseBody.getType(), protectionAlgorithmName(request.getHeader()));
            }
            final CredentialContext reusedCredentials = buildReusedCredentialContext(request);
            final MsgOutputProtector protector;
            if (reusedCredentials instanceof SharedSecretCredentialContext) {
                // PasswordBasedMac request: answer with the mirrored PBM
                // credentials. The NestedEndpointContext constructor takes the
                // credentials directly and keeps all other output settings
                // (e.g. recipient) from the upstream configuration.
                protector = new MsgOutputProtector(
                        new NestedEndpointContext() {
                            @Override
                            public VerificationContext getInputVerification() {
                                return null;
                            }

                            @Override
                            public CredentialContext getOutputCredentials() {
                                return reusedCredentials;
                            }

                            @Override
                            public String getRecipient() {
                                return upstreamConfig.getRecipient();
                            }

                            @Override
                            public boolean isIncomingRecipientValid(final String incomingSigner) {
                                // Outbound-only context inside the upstream
                                // callback: no inbound validation is performed.
                                return true;
                            }
                        },
                        StreamType.upstream(UPSTREAM_INTERFACE_NAME),
                        reusedCredentials);
            } else if (isSignatureProtectedRequest(request)) {
                // Signature-protected request: embed the signer certificate of
                // the request as sole extraCert of the generated response.
                // See buildEchoedExtraCertsInterface() for the rationale.
                protector = new MsgOutputProtector(
                        buildEchoedExtraCertsInterface(upstreamConfig, request),
                        StreamType.upstream(UPSTREAM_INTERFACE_NAME),
                        (MessageContext) null);
            } else {
                // No reusable credentials (unprotected or PBMAC1 protected
                // request): protect with the configured upstream output
                // credentials (the gateway certificate).
                protector = new MsgOutputProtector(
                        upstreamConfig,
                        StreamType.upstream(UPSTREAM_INTERFACE_NAME),
                        (MessageContext) null);
            }
            final PKIMessage protectedResponse =
                    protector.generateAndProtectResponseTo(request, responseBody);
            return isSignatureProtectedRequest(request)
                    ? reSignWithClientKey(protectedResponse, request)
                    : protectedResponse;
        }

        /**
         * True if the request carries signature-based protection (i.e. neither
         * unprotected, nor PasswordBasedMac, nor PBMAC1).
         */
        private static boolean isSignatureProtectedRequest(final PKIMessage request) {
            final org.bouncycastle.asn1.x509.AlgorithmIdentifier protectionAlg =
                    request.getHeader().getProtectionAlg();
            if (protectionAlg == null) {
                return false;
            }
            final ASN1ObjectIdentifier oid = protectionAlg.getAlgorithm();
            return !org.bouncycastle.asn1.cmp.CMPObjectIdentifiers.passwordBasedMac.equals(oid)
                    && !org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_PBMAC1.equals(oid);
        }

        /**
         * Wrap the upstream {@link CmpMessageInterface} used to protect a
         * self-generated response to a signature-protected request.
         *
         * <p>Problem being solved: the RA component runs the full upstream
         * validation chain ({@code ProtectionValidator} ->
         * {@code SignatureProtectionValidator}) over everything this callback
         * returns. That validator takes the <em>first extraCert of the
         * response</em> as protection certificate and must be able to build a
         * PKIX path for it against the trust anchors returned by
         * {@code GatewayConfig.getUpstreamConfiguration().getInputVerification()}
         * (the CA chain fetched from CEMA via GET /ca/{caName}/chain). The
         * gateway's own client certificate (e.g. "CN=CEMA Admin" issued by
         * "BoarderZone Dev CA") can never build such a path to the enrollment
         * CA ("CEMA User CA"), so signing the CertRep with it failed with
         * "validating the protection certificate failed" (signerNotTrusted).</p>
         *
         * <p>Fix: report the request's signer certificate(s) as the output
         * credential chain. {@code MsgOutputProtector} then embeds exactly those
         * certificates into the response's extraCerts, so the validator picks
         * the client's own signer as protecting certificate - a certificate the
         * client itself demonstrably possesses and that is covered by the
         * downstream acceptance policy. The signature bytes are still produced
         * with the gateway keystore key at this stage; when the client actually
         * holds a different key, {@link #reSignWithClientKey(PKIMessage, PKIMessage)}
         * replaces them with a real signature over the echoed certificate.</p>
         */
        private static CmpMessageInterface buildEchoedExtraCertsInterface(
                final CmpMessageInterface base, final PKIMessage request) {
            final CMPCertificate[] signerCandidates = request.getExtraCerts();
            if (signerCandidates == null || signerCandidates.length == 0) {
                // Nothing to echo: keep the standard behaviour (gateway signer
                // in extraCerts). Validation may still fail, but there is no
                // usable alternative.
                return base;
            }
            return new CmpMessageInterface() {
                @Override
                public VerificationContext getInputVerification() {
                    final VerificationContext baseVerification = base.getInputVerification();
                    if (baseVerification == null) {
                        return null;
                    }
                    // The echoed signer is the EE's own enrollment certificate,
                    // which cannot build a PKIX path to the CA chain anchors
                    // before it was issued. Trust exactly this one certificate
                    // without path validation; keep the normal trust anchors for
                    // everything else.
                    return new VerificationContext() {
                        @Override
                        public Collection<X509Certificate> getTrustedCertificates() {
                            try {
                                return CertUtility.asX509Certificates(signerCandidates);
                            } catch (final java.security.cert.CertificateException ex) {
                                return baseVerification.getTrustedCertificates();
                            }
                        }

                        @Override
                        public Collection<X509Certificate> getAdditionalCerts() {
                            return baseVerification.getAdditionalCerts();
                        }

                        @Override
                        public byte[] getSharedSecret(final byte[] senderKID) {
                            return baseVerification.getSharedSecret(senderKID);
                        }

                        @Override
                        public boolean isLeafCertAcceptable(final X509Certificate cert) {
                            return true;
                        }

                        @Override
                        public boolean isIntermediateCertAcceptable(final X509Certificate cert) {
                            return true;
                        }
                    };
                }

                @Override
                public NestedEndpointContext getNestedEndpointContext() {
                    return base.getNestedEndpointContext();
                }

                @Override
                public CredentialContext getOutputCredentials() {
                    try {
                        final List<X509Certificate> echoedChain =
                                CertUtility.asX509Certificates(signerCandidates);
                        return new SignatureCredentialContext() {
                            @Override
                            public List<X509Certificate> getCertificateChain() {
                                return echoedChain;
                            }

                            @Override
                            public java.security.PrivateKey getPrivateKey() {
                                try {
                                    return base.getOutputCredentials()
                                            instanceof SignatureCredentialContext
                                        ? ((SignatureCredentialContext) base.getOutputCredentials())
                                                .getPrivateKey()
                                        : null;
                                } catch (final Exception ex) {
                                    return null;
                                }
                            }
                        };
                    } catch (final java.security.cert.CertificateException ex) {
                        LOG.warn("could not convert request extraCerts for echoing", ex);
                        return base.getOutputCredentials();
                    }
                }

                @Override
                public ReprotectMode getReprotectMode() {
                    return base.getReprotectMode();
                }

                @Override
                public boolean isEnforceReprotectMode() {
                    return base.isEnforceReprotectMode();
                }

                @Override
                public boolean getSuppressRedundantExtraCerts() {
                    return base.getSuppressRedundantExtraCerts();
                }

                @Override
                public boolean isCacheExtraCerts() {
                    return base.isCacheExtraCerts();
                }

                @Override
                public boolean isMessageTimeDeviationAllowed(final long deviation) {
                    return base.isMessageTimeDeviationAllowed(deviation);
                }

                @Override
                public String getRecipient() {
                    return base.getRecipient();
                }
            };
        }

        /**
         * Re-sign an upstream response whose extraCerts echo the signer of the
         * related request. If the gateway keystore key matches the echoed leaf
         * (typical for self-signed LCMP test clients), the existing signature is
         * already valid and nothing is done. Otherwise the message is signed
         * again with the client's own key - loaded from the configured keystore
         * by matching the certificate's subject/serial against every key entry
         * - so that the signature verifies against the echoed certificate. If no
         * matching key exists locally, the message is returned unchanged and the
         * RA component's validation will reject it with a clear log entry.
         */
        private PKIMessage reSignWithClientKey(final PKIMessage response, final PKIMessage request)
                throws IOException {
            final CMPCertificate[] extraCerts = response.getExtraCerts();
            if (extraCerts == null || extraCerts.length == 0) {
                return response;
            }
            try {
                final X509Certificate signer = CertUtility.asX509Certificate(extraCerts[0]);
                final PrivateKey keystoreKey = config.getPrivateKey();
                if (keystoreKey != null && privateKeyMatchesCertificate(keystoreKey, signer)) {
                    // The echoed signer is the keystore certificate itself; the
                    // MsgOutputProtector signature is valid as-is.
                    return response;
                }
                final PrivateKey clientKey = findMatchingPrivateKey(signer);
                if (clientKey == null) {
                    LOG.warn("cannot re-sign the upstream response with the EE key for signer '{}': "
                            + "no matching private key found in the gateway keystore; the RA component "
                            + "will reject the response unless the keystore key happens to match",
                            signer.getSubjectX500Principal());
                    return response;
                }
                final String signatureAlgorithm = AlgorithmHelper.getSigningAlgNameFromKey(clientKey);
                final java.security.Signature sig = AlgorithmHelper.getSignature(signatureAlgorithm);
                sig.initSign(clientKey);
                sig.update(new ProtectedPart(response.getHeader(), response.getBody())
                        .getEncoded(ASN1Encoding.DER));
                final DERBitString protection = new DERBitString(sig.sign());
                LOG.info("upstream response re-signed with the EE key matching its own signer "
                        + "certificate '{}' (algorithm {})",
                        signer.getSubjectX500Principal(), signatureAlgorithm);
                return new PKIMessage(
                        PKIHeader.getInstance(response.getHeader().toASN1Primitive()),
                        response.getBody(),
                        protection,
                        response.getExtraCerts());
            } catch (final Exception ex) {
                throw new IOException("could not re-sign the self-generated upstream response", ex);
            }
        }

        /**
         * Search the configured PKCS#12 keystore for a private key whose
         * certificate chain starts with (or contains) the given certificate.
         */
        private PrivateKey findMatchingPrivateKey(final X509Certificate certificate) {
            try {
                final java.security.KeyStore ks = config.loadKeyStore();
                if (ks == null) {
                    return null;
                }
                final char[] password = config.getKeystorePassword() == null
                        ? new char[0]
                        : config.getKeystorePassword().toCharArray();
                final java.util.Enumeration<String> aliases = ks.aliases();
                while (aliases.hasMoreElements()) {
                    final String alias = aliases.nextElement();
                    if (!ks.isKeyEntry(alias)) {
                        continue;
                    }
                    final java.security.cert.Certificate[] chain = ks.getCertificateChain(alias);
                    boolean matches = false;
                    if (chain != null) {
                        for (final java.security.cert.Certificate c : chain) {
                            if (c instanceof X509Certificate
                                    && Arrays.equals(
                                            ((X509Certificate) c).getEncoded(), certificate.getEncoded())) {
                                matches = true;
                                break;
                            }
                        }
                    }
                    if (!matches) {
                        continue;
                    }
                    final java.security.Key key = ks.getKey(alias, password);
                    if (key instanceof PrivateKey) {
                        return (PrivateKey) key;
                    }
                }
                return null;
            } catch (final Exception ex) {
                LOG.debug("keystore scan for a private key matching the EE signer failed", ex);
                return null;
            }
        }

        /**
         * Decide whether a private key belongs to a given certificate. RSA and
         * EC keys are compared by their public parameters; anything else falls
         * back to a sign/verify round trip.
         */
        private static boolean privateKeyMatchesCertificate(
                final PrivateKey privateKey, final X509Certificate certificate) {
            final java.security.PublicKey publicKey = certificate.getPublicKey();
            if (privateKey instanceof java.security.interfaces.RSAPrivateKey
                    && publicKey instanceof java.security.interfaces.RSAPublicKey) {
                return ((java.security.interfaces.RSAPrivateKey) privateKey).getModulus()
                        .equals(((java.security.interfaces.RSAPublicKey) publicKey).getModulus());
            }
            if (privateKey instanceof java.security.interfaces.ECPrivateKey
                    && publicKey instanceof java.security.interfaces.ECPublicKey) {
                return ((java.security.interfaces.ECPrivateKey) privateKey).getS()
                        .bitLength() > 0
                        && ((java.security.interfaces.ECPrivateKey) privateKey).getParams().equals(
                                ((java.security.interfaces.ECPublicKey) publicKey).getParams())
                        && verifyRoundTrip(privateKey, publicKey);
            }
            return verifyRoundTrip(privateKey, publicKey);
        }

        private static boolean verifyRoundTrip(
                final PrivateKey privateKey, final java.security.PublicKey publicKey) {
            try {
                final String alg = pickSignatureAlgorithm(publicKey);
                final java.security.Signature sig = java.security.Signature.getInstance(alg);
                sig.initSign(privateKey);
                sig.update(new byte[] {'k', 'i', 'd'});
                final byte[] signature = sig.sign();
                sig.initVerify(publicKey);
                sig.update(new byte[] {'k', 'i', 'd'});
                return sig.verify(signature);
            } catch (final Exception ex) {
                return false;
            }
        }

        private static String pickSignatureAlgorithm(final java.security.PublicKey publicKey) {
            switch (publicKey.getAlgorithm()) {
                case "RSA": return "SHA256withRSA";
                case "EC": return "SHA256withECDSA";
                case "Ed25519": return "Ed25519";
                case "Ed448": return "Ed448";
                case "DSA": return "SHA256withDSA";
                default: return publicKey.getAlgorithm();
            }
        }

        /**
         * Human-readable name of the protection algorithm in a PKI header, for logging.
         */
        private static String protectionAlgorithmName(final org.bouncycastle.asn1.cmp.PKIHeader header) {
            final org.bouncycastle.asn1.x509.AlgorithmIdentifier alg = header.getProtectionAlg();
            if (alg == null) {
                return "none";
            }
            final String oid = alg.getAlgorithm().getId();
            if (org.bouncycastle.asn1.cmp.CMPObjectIdentifiers.passwordBasedMac.equals(alg.getAlgorithm())) {
                return "PasswordBasedMac (" + oid + ")";
            }
            if (org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_PBMAC1.equals(alg.getAlgorithm())) {
                return "PBMAC1 (" + oid + ")";
            }
            return "signature (" + oid + ")";
        }

        /**
         * Derive the credential context to protect an upstream response with,
         * mirroring the protection of the related downstream request. Returns
         * {@code null} if no credentials can be reused, which makes
         * {@link MsgOutputProtector} fall back to the configured upstream
         * output credentials.
         */
        private CredentialContext buildReusedCredentialContext(final PKIMessage request) {
            final org.bouncycastle.asn1.cmp.PKIHeader header = request.getHeader();
            final org.bouncycastle.asn1.x509.AlgorithmIdentifier protectionAlg = header.getProtectionAlg();
            if (protectionAlg == null) {
                // Unprotected request - nothing to mirror.
                return null;
            }
            if (org.bouncycastle.asn1.cmp.CMPObjectIdentifiers.passwordBasedMac
                    .equals(protectionAlg.getAlgorithm())) {
                final org.bouncycastle.asn1.cmp.PBMParameter pbmParameter =
                        org.bouncycastle.asn1.cmp.PBMParameter.getInstance(protectionAlg.getParameters());
                final byte[] sharedSecret = config.getSharedSecret();
                if (sharedSecret == null || sharedSecret.length == 0) {
                    LOG.warn("request is password-mac protected but no shared secret is configured; "
                            + "falling back to upstream output credentials");
                    return null;
                }
                // Mirror the exact PBM parameter set of the request so that the
                // client can verify our response with the same key derivation.
                final ASN1OctetString salt = pbmParameter.getSalt();
                final int iterationCount = pbmParameter.getIterationCount().intValueExact();
                final String macAlgorithm = mapHmacOidToName(pbmParameter.getMac().getAlgorithm());
                final String prf = mapDigestOidToName(pbmParameter.getOwf().getAlgorithm());
                final ASN1OctetString senderKid = header.getSenderKID();
                return new SharedSecretCredentialContext() {
                    @Override
                    public byte[] getSharedSecret() {
                        return sharedSecret;
                    }

                    @Override
                    public String getPasswordBasedMacAlgorithm() {
                        return "PasswordBasedMac";
                    }

                    @Override
                    public byte[] getSalt() {
                        return salt.getOctets();
                    }

                    @Override
                    public int getIterationCount() {
                        return iterationCount;
                    }

                    @Override
                    public String getMacAlgorithm() {
                        return macAlgorithm;
                    }

                    @Override
                    public String getPrf() {
                        return prf;
                    }

                    @Override
                    public byte[] getSenderKID() {
                        return senderKid == null ? null : senderKid.getOctets();
                    }
                };
            }
            if (org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_PBMAC1
                    .equals(protectionAlg.getAlgorithm())) {
                LOG.info("PBMAC1-protected request detected; PBMAC1 parameters cannot be reused "
                        + "for the response, protecting with the configured upstream output credentials");
                return null;
            }
            // Signature-based (or unknown) protection: respond with the
            // configured upstream output credentials. The gateway certificate is
            // embedded in extraCerts by MsgOutputProtector, so clients that look
            // up our signer certificate by key identifier do not need a
            // senderKID echo here.
            LOG.debug("request is protected with {}; answering with the configured upstream "
                    + "output credentials (gateway certificate)",
                    protectionAlgorithmName(header));
            return null;
        }

        /**
         * Map an HMAC algorithm OID (e.g. id-hmacWithSHA256) to the JCE MAC
         * algorithm name expected by {@code SharedSecretCredentialContext#getMacAlgorithm()}.
         */
        private static String mapHmacOidToName(final org.bouncycastle.asn1.ASN1ObjectIdentifier oid) {
            final String id = oid.getId();
            switch (id) {
                case "1.2.840.113549.2.7": return "HMACSHA1";
                case "1.2.840.113549.2.8": return "HMACSHA224";
                case "1.2.840.113549.2.9": return "HMACSHA256";
                case "1.2.840.113549.2.10": return "HMACSHA384";
                case "1.2.840.113549.2.11": return "HMACSHA512";
                default: return id; // passed through as-is; may already be a JCE name
            }
        }

        /**
         * Map a digest algorithm OID (used as PBM OWF/PRF) to the JCE
         * MessageDigest name expected by {@code SharedSecretCredentialContext#getPrf()}.
         */
        private static String mapDigestOidToName(final org.bouncycastle.asn1.ASN1ObjectIdentifier oid) {
            final String id = oid.getId();
            switch (id) {
                case "1.2.840.113549.2.5": return "SHA1";
                case "2.16.840.1.101.3.4.2.4": return "SHA224";
                case "2.16.840.1.101.3.4.2.1": return "SHA256";
                case "2.16.840.1.101.3.4.2.2": return "SHA384";
                case "2.16.840.1.101.3.4.2.3": return "SHA512";
                default: return "SHA256";
            }
        }
    }

    private static PKIMessage parseMessage(final byte[] encoded) throws IOException {
        try (ASN1InputStream input = new ASN1InputStream(encoded)) {
            return PKIMessage.getInstance(input.readObject());
        }
    }

    private final class CmpHandler implements HttpHandler {
        @Override
        public void handle(final HttpExchange exchange) throws IOException {
            try (exchange) {
                if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                final byte[] response = cmpRaInterface.processRequest(exchange.getRequestBody().readAllBytes());
                if (response == null) {
                    exchange.sendResponseHeaders(204, -1);
                    return;
                }
                exchange.getResponseHeaders().set("Content-Type", "application/pkixcmp");
                exchange.sendResponseHeaders(200, response.length);
                exchange.getResponseBody().write(response);
            } catch (Exception exception) {
                LOG.error("CMP request failed", exception);
                final byte[] body = ("CMP request failed: " + exception.getMessage())
                        .getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(500, body.length);
                exchange.getResponseBody().write(body);
            }
        }
    }

    public void start() {
        httpServer.start();
        LOG.info("CMP gateway listening on {}{}", httpServer.getAddress().getPort(), config.getCmpPath());
    }

    public void stop() {
        httpServer.stop(5);
        executor.shutdown();
    }
}
