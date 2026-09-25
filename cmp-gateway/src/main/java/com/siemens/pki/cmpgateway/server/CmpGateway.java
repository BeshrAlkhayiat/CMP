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
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
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
            // INFO level on purpose: this shows which protection the incoming EE
            // request actually carries - the single most important diagnostic for
            // the "validating the protection certificate failed" issue.
            LOG.info("upstream callback: body type {}, sender='{}', protection={}, extraCerts={}",
                    bodyType,
                    message.getHeader().getSender() == null
                            ? null : message.getHeader().getSender().getName(),
                    protectionAlgorithmName(message.getHeader()),
                    message.getExtraCerts() == null ? 0 : message.getExtraCerts().length);
            if (LOG.isDebugEnabled()) {
                LOG.debug("upstream callback: senderKID form {}",
                        message.getHeader().getSenderKID() == null
                                ? "none"
                                : message.getHeader().getSenderKID()
                                        .toASN1Primitive().getClass().getSimpleName());
            }
            // Remember the transaction of the request being processed so that the
            // generated upstream responses can be protected with the matching
            // credentials (see protectUpstreamResponse).
            final PersistencyContext persistencyContext = new PersistencyContext();
            persistencyContext.setRequestType(bodyType);
            currentTransaction.set(persistencyContext);
            // Everything returned from this callback is generated by the gateway
            // itself and protected with the gateway signer certificate, which is
            // typically not issued by the enrollment CA. The RA component re-validates
            // signature-based protection of upstream messages, including these
            // self-generated responses (SignatureProtectionValidator runs after this
            // callback returns): it verifies the CMPCertificate[] form of the header's
            // senderKID against the message signature and then demands a PKIX path for
            // it against the anchors from getUpstreamConfiguration().getInputVerification()
            // (the CEMA CA chain). The gateway keystore key cannot sign for the EE's
            // senderKID, so the response must carry the gateway's own signer identity:
            // tell GatewayConfig to add the gateway keystore chain as extra trust anchor
            // (see selfGeneratedUpstreamMessage) and override senderKID accordingly in
            // protectUpstreamResponse().
            // IMPORTANT: the flag must NOT be cleared in this callback's finally
            // block - the RA validates the returned message AFTER this method has
            // already completed (observed live: trust anchor query with
            // "in progress=false" during validation of our own CertRep). The
            // volatile flag stays set until the whole downstream request finished;
            // it is cleared in CmpHandler.handle below.
            if (isSignatureProtectedRequest(message)) {
                // Only signature-protected EE requests lead to a self-generated,
                // signature-protected CertRep (see protectUpstreamResponse). PBM
                // answers reuse the request's MAC credentials and never touch the
                // PKIX anchor path - keep the merge off for them so the gateway's
                // REST-auth (Tomcat) certificate can never become a CMP trust
                // anchor outside this narrow case.
                config.setProcessingSelfGeneratedUpstreamMessage(true);
            }
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
                // NOTE: the self-generated-upstream flag is deliberately NOT cleared
                // here - the RA component validates the message returned from this
                // callback only afterwards (see comment above). It is cleared once per
                // downstream request in handleDownstreamRequest().
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
            } else {
                // Signature-protected, unprotected or PBMAC1 protected request:
                // protect the generated response with the configured upstream
                // output credentials (the gateway certificate from
                // auth.keystore.path). The RA component re-validates this
                // self-generated protection certificate against the upstream
                // trust anchors; GatewayConfig.getUpstreamConfiguration()
                // merges the gateway keystore chain into those anchors while a
                // self-generated message is being validated, so it passes.
                final X509Certificate signer = getGatewaySignerCertificate();
                LOG.info("protecting self-generated upstream response with the gateway "
                                + "signature credential: subject='{}', issuer='{}'",
                        signer == null ? "<not available>" : signer.getSubjectX500Principal(),
                        signer == null ? "<not available>" : signer.getIssuerX500Principal());
                protector = new MsgOutputProtector(
                        upstreamConfig,
                        StreamType.upstream(UPSTREAM_INTERFACE_NAME),
                        (MessageContext) null);
            }
            final PKIMessage generated = protector.generateAndProtectResponseTo(request, responseBody);
            // RFC 4210 section 5.1.3.1.3 / RFC 9483 section 3.2: a CMP server MUST
            // send all issuer-side certificates needed to build a certification path
            // for the issued certificate in the extraCerts field of the CertRep (the
            // CA certificates are normally sent with every response). The LCMP client
            // stack builds its enrollment chain exclusively from these extraCerts
            // (see CmpClient.invokeEnrollment -> TrustCredentialAdapter.
            // validateCertAgainstTrust(issued cert, asX509Certificates(extraCerts))),
            // so without them getEnrollmentChain() comes back null and enrollment
            // fails client-side. MsgOutputProtector only embeds the signer's own
            // chain here, so append the CA chain fetched via GET /ca/{caName}/chain.
            final PKIMessage protectedResponse = appendCaChainExtraCerts(generated);
            // Diagnostic: what the RA downstream stage will see when it validates the
            // trust chain of the ISSUED certificate - its only path-building material
            // is the extraCerts list of this message (RaDownstream.processCertResponse
            // calls validateCertAgainstTrust(issued cert, asX509Certificates(extraCerts))).
            LOG.info("self-generated upstream response ready: body type {}, granted={}, "
                            + "extraCerts={} -> [{}]",
                    responseBody.getType(),
                    describeGrantStatus(responseBody),
                    protectedResponse.getExtraCerts() == null ? 0 : protectedResponse.getExtraCerts().length,
                    describeExtraCerts(protectedResponse));
            if (!isSignatureProtectedRequest(request)) {
                return protectedResponse;
            }
            // The generated header already identifies the gateway signer correctly:
            // PkiMessageGenerator takes sender and senderKID from the signature
            // protection provider (SKI of the gateway leaf) and only copies pvno,
            // transactionID and nonces from the request. What is missing for a
            // signature-protected request is the CMPCertificate[] senderKID form
            // (RFC 4210 choice cmPCertificate): LCMP clients send it that way and
            // expect the answer in the same form; SignatureProtectionValidator would
            // otherwise compare the EE's embedded-certificate KID bytes with the
            // gateway SKI. Convert the header KID to that form when the request used
            // it - BC stores a CMPCertificate[] senderKID as an OCTET STRING wrapping
            // the SEQUENCE of embedded certificates. extraCerts already contain the
            // gateway chain and GatewayConfig.getUpstreamConfiguration() merges the
            // gateway keystore chain into the trust anchors while a self-generated
            // message is being validated, so the PKIX check passes too.
            final X509Certificate gatewaySigner = getGatewaySignerCertificate();
            if (gatewaySigner == null) {
                LOG.warn("cannot rewrite senderKID of the self-generated signature-"
                        + "protected upstream response: gateway signer certificate not"
                        + " available");
                return protectedResponse;
            }
            if (!(request.getHeader().getSenderKID().toASN1Primitive() instanceof DERBitString)) {
                // Request used the subject key identifier form (or no KID at all):
                // the generated header already matches the gateway signer.
                return protectedResponse;
            }
            try {
                final ASN1OctetString newKid = new DEROctetString(new DERSequence(
                        CMPCertificate.getInstance(gatewaySigner.getEncoded())));
                final PKIHeader requestHeader = protectedResponse.getHeader();
                final PKIHeaderBuilder rewrittenHeader = new PKIHeaderBuilder(
                        requestHeader.getPvno().intValueExact(),
                        requestHeader.getSender(),
                        requestHeader.getRecipient());
                rewrittenHeader.setMessageTime(requestHeader.getMessageTime());
                rewrittenHeader.setProtectionAlg(requestHeader.getProtectionAlg());
                rewrittenHeader.setSenderKID(newKid);
                rewrittenHeader.setTransactionID(requestHeader.getTransactionID());
                rewrittenHeader.setSenderNonce(requestHeader.getSenderNonce());
                rewrittenHeader.setRecipNonce(requestHeader.getRecipNonce());
                rewrittenHeader.setGeneralInfo(requestHeader.getGeneralInfo());
                return new PKIMessage(rewrittenHeader.build(), protectedResponse.getBody(),
                        protectedResponse.getProtection(), protectedResponse.getExtraCerts());
            } catch (final Exception ex) {
                throw new IOException("could not rewrite senderKID of the self-generated"
                        + " signature-protected upstream response", ex);
            }
        }

        /**
         * Diagnostic helper: short description of the CertRep status for logging.
         */
        private static String describeGrantStatus(final PKIBody responseBody) {
            try {
                if (responseBody.getContent() instanceof org.bouncycastle.asn1.cmp.CertRepMessage) {
                    final org.bouncycastle.asn1.cmp.CertRepMessage rep =
                            (org.bouncycastle.asn1.cmp.CertRepMessage) responseBody.getContent();
                    if (rep.getResponse() != null && rep.getResponse().length > 0) {
                        return String.valueOf(rep.getResponse()[0].getStatus().getStatus());
                    }
                }
            } catch (final Exception ex) {
                // diagnostic only - never fail the real flow because of logging
            }
            return "n/a";
        }

        /**
         * Diagnostic helper: subject/issuer of every certificate embedded in the
         * extraCerts of a message. The RA downstream validation of the issued
         * certificate builds its PKIX path using ONLY these certificates plus the
         * enrollment trust anchors, so this list tells you whether the issuing CA
         * chain from CEMA actually made it into the CertRep.
         */
        private static String describeExtraCerts(final PKIMessage message) {
            final org.bouncycastle.asn1.cmp.CMPCertificate[] extra = message.getExtraCerts();
            if (extra == null || extra.length == 0) {
                return "";
            }
            final StringBuilder sb = new StringBuilder();
            for (final org.bouncycastle.asn1.cmp.CMPCertificate c : extra) {
                try {
                    final X509Certificate x = CertUtility.asX509Certificate(c);
                    if (sb.length() > 0) {
                        sb.append(", ");
                    }
                    // Diagnostic detail: the RA component's TrustCredentialAdapter drops
                    // every extraCert that is not marked as a CA certificate (BasicConstraints
                    // cA=true, see CertUtility.isIntermediateCertificate / BC's
                    // X509CertificateHolder.isCA) when collecting path-building material, and
                    // JDK PKIX ignores non-CA candidates entirely. A cert with a missing or
                    // non-critical BasicConstraints extension therefore silently breaks chain
                    // building even though subject/issuer names look perfect - which is exactly
                    // what "error building enrollment chain" (client) / "could not validate
                    // trust chain of issued certificate" (RA downstream) looked like here.
                    sb.append(x.getSubjectX500Principal().getName())
                            .append(" <- ")
                            .append(x.getIssuerX500Principal().getName());
                    try {
                        final int bc = x.getBasicConstraints();
                        sb.append(" [BC=").append(bc < 0 ? "none/leaf" : ("critical,pathLen=" + bc))
                                .append(", KU=").append(keyUsageToString(x.getKeyUsage()))
                                .append("]");
                    } catch (final Exception ignored) {
                        // extension parsing is diagnostic only
                    }
                } catch (final Exception ex) {
                    if (sb.length() > 0) {
                        sb.append(", ");
                    }
                    sb.append("<unreadable>");
                }
            }
            return sb.toString();
        }

        /**
         * Diagnostic helper: render the key usage bits of a certificate compactly.
         */
        private static String keyUsageToString(final boolean[] ku) {
            if (ku == null) {
                return "none";
            }
            final String[] names = {"digitalSignature", "nonRepudiation", "keyEncipherment",
                    "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign",
                    "encipherOnly", "decipherOnly"};
            final StringBuilder sb = new StringBuilder();
            for (int i = 0; i < ku.length && i < names.length; i++) {
                if (ku[i]) {
                    if (sb.length() > 0) {
                        sb.append('|');
                    }
                    sb.append(names[i]);
                }
            }
            return sb.length() == 0 ? "empty" : sb.toString();
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
         * Append the CA chain (fetched via GET /ca/{caName}/chain) to the extraCerts
         * of a self-generated CertRep, as required by RFC 4210 section 5.1.3.1.3 and
         * RFC 9483 section 3.2: the server must deliver all certificates needed to
         * build a certification path for the issued certificate with every response.
         * LCMP clients have no other source for these issuer-side certificates -
         * without them getEnrollmentChain() returns null on the client side.
         */
        private PKIMessage appendCaChainExtraCerts(final PKIMessage message) {
            try {
                final List<X509Certificate> caChain = config.getAutomaticallyFetchedCaChain();
                if (caChain == null || caChain.isEmpty()) {
                    return message;
                }
                final org.bouncycastle.asn1.cmp.CMPCertificate[] old =
                        message.getExtraCerts() == null
                                ? new org.bouncycastle.asn1.cmp.CMPCertificate[0]
                                : message.getExtraCerts();
                final java.util.List<org.bouncycastle.asn1.cmp.CMPCertificate> merged =
                        new ArrayList<>(Arrays.asList(old));
                int added = 0;
                for (final X509Certificate cert : caChain) {
                    final org.bouncycastle.asn1.cmp.CMPCertificate cmpCert =
                            org.bouncycastle.asn1.cmp.CMPCertificate.getInstance(
                                    cert.getEncoded());
                    // Skip duplicates (e.g. gateway signer chain already embedded by
                    // MsgOutputProtector, or a CA cert that is also a trust anchor).
                    if (!containsEncoded(merged, cmpCert)) {
                        merged.add(cmpCert);
                        added++;
                    }
                }
                if (added == 0) {
                    return message;
                }
                LOG.info("appended {} CA certificate(s) from '{}' to the extraCerts of the "
                                + "self-generated upstream response (RFC 4210 5.1.3.1.3)",
                        added, "GET /ca/" + config.getCaName() + "/chain");
                return new PKIMessage(message.getHeader(), message.getBody(),
                        message.getProtection(),
                        merged.toArray(new org.bouncycastle.asn1.cmp.CMPCertificate[0]));
            } catch (final Exception ex) {
                // Never fail the enrollment because of the convenience chain; the
                // client may still hold the CA certificates itself.
                LOG.warn("could not append the CA chain to the extraCerts of the "
                        + "self-generated upstream response", ex);
                return message;
            }
        }

        private static boolean containsEncoded(
                final java.util.List<org.bouncycastle.asn1.cmp.CMPCertificate> list,
                final org.bouncycastle.asn1.cmp.CMPCertificate candidate)
                throws java.io.IOException {
            final byte[] encoded = candidate.getEncoded(ASN1Encoding.DER);
            for (final org.bouncycastle.asn1.cmp.CMPCertificate existing : list) {
                if (Arrays.equals(existing.getEncoded(ASN1Encoding.DER), encoded)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * The leaf certificate of the gateway keystore (auth.keystore.path), i.e.
         * the certificate the RA component signs self-generated upstream responses
         * with. Null if no keystore is configured or it cannot be read.
         */
        private X509Certificate getGatewaySignerCertificate() {
            try {
                final List<X509Certificate> chain = config.getCertificateChain();
                return chain == null || chain.isEmpty() ? null : chain.get(0);
            } catch (final Exception ex) {
                LOG.warn("could not load the gateway keystore certificate chain", ex);
                return null;
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
                // The RA component may set (via our upstream exchange callback) the
                // "self-generated upstream message" flag in GatewayConfig to merge the
                // gateway keystore chain into the upstream trust anchors. That flag is
                // intentionally kept until validation finished - clear it here, once
                // per downstream request, after processRequest returned/failed.
                final byte[] response;
                try {
                    response = cmpRaInterface.processRequest(exchange.getRequestBody().readAllBytes());
                } finally {
                    config.setProcessingSelfGeneratedUpstreamMessage(false);
                }
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
