/*
 *  Copyright (c) 2024 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 */
package com.siemens.pki.cmpgateway.server;

import com.siemens.pki.cmpracomponent.configuration.CmpMessageInterface;
import com.siemens.pki.cmpracomponent.configuration.Configuration;
import com.siemens.pki.cmpracomponent.configuration.CredentialContext;
import com.siemens.pki.cmpracomponent.configuration.SharedSecretCredentialContext;
import com.siemens.pki.cmpracomponent.configuration.VerificationContext;
import com.siemens.pki.cmpracomponent.cryptoservices.AlgorithmHelper;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpracomponent.msggeneration.MsgOutputProtector;
import com.siemens.pki.cmpracomponent.msggeneration.PkiMessageGenerator;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageContext;
import com.siemens.pki.cmpracomponent.msgvalidation.MessageHeaderValidator;
import com.siemens.pki.cmpracomponent.persistency.PersistencyContext;
import com.siemens.pki.cmpracomponent.msgprocessing.StreamType;
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
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
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
import org.bouncycastle.asn1.x509.Certificate;
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
        this.cmpRaInterface = CmpRaComponent.instantiateCmpRaComponent(config, new RestUpstream());
        this.httpServer = HttpServer.create(new InetSocketAddress(config.getCmpPort()), 0);
        httpServer.createContext(config.getCmpPath(), new CmpHandler());
        httpServer.setExecutor(executor);
    }

    private final class RestUpstream implements UpstreamExchange, CmpRaComponent.GeneratedKeyProvider {
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
            switch (bodyType) {
                case PKIBody.TYPE_P10_CERT_REQ:
                    return issuePkcs10(message, certProfile);
                case PKIBody.TYPE_REVOCATION_REQ:
                    return revoke(message);
                case PKIBody.TYPE_INIT_REQ:
                case PKIBody.TYPE_CERT_REQ:
                case PKIBody.TYPE_KEY_UPDATE_REQ:
                    return processCrmf(message, certProfile);
                default:
                    throw new UnsupportedOperationException(
                            "LCMP body type " + bodyType + " is not mapped to CEMA");
            }
        }

        private byte[] processCrmf(final PKIMessage request, final String certProfile) throws Exception {
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
                return issueCrmf(request, certReqMsg, certProfile);
            }
            return generateCentralKey(request, certReqMsg);
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

        private byte[] issueCrmf(
                final PKIMessage request, final CertReqMsg certReqMsg, final String certProfile) {
            throw new UnsupportedOperationException(
                    "ordinary CRMF issuance (with subject public key) is not representable by the "
                            + "available CEMA REST API");
        }

        private byte[] generateCentralKey(final PKIMessage request, final CertReqMsg certReqMsg)
                throws Exception {
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
                    request, certReqMsg.getCertReq().getCertReqId().getValue(), certificate);
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
        private byte[] issuePkcs10(final PKIMessage request, final String certProfile) throws Exception {
            final CertificationRequest csr =
                    CertificationRequest.getInstance(request.getBody().getContent());
            // If no lookup is configured (or it is blank or the unused default), use the direct
            // template-based endpoint /ca/{caName}/template/{tplName}/issue instead of auto-issue.
            final String lookup = config.getLookupName();
            final boolean useLookup = lookup != null && !lookup.isBlank() && !"default".equals(lookup);
            final RestClient.CertificateResult result = useLookup
                    ? restClient.autoIssueCertificate(Base64.getEncoder().encodeToString(csr.getEncoded()))
                    : restClient.issueCertificate(Base64.getEncoder().encodeToString(csr.getEncoded()));
            return certificateResponse(request, BigInteger.ZERO, awaitCertificate(result));
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

        private byte[] revoke(final PKIMessage request) throws Exception {
            final RevReqContent content = RevReqContent.getInstance(request.getBody().getContent());
            if (content.toRevDetailsArray().length == 0
                    || content.toRevDetailsArray()[0].getCertDetails().getSerialNumber() == null) {
                throw new IllegalArgumentException("revocation request does not contain a certificate serial number");
            }
            final BigInteger serial =
                    content.toRevDetailsArray()[0].getCertDetails().getSerialNumber().getValue();
            restClient.revokeCertificate(serial.toString(), 0);
            final PKIBody responseBody = new PKIBody(
                    PKIBody.TYPE_REVOCATION_REP,
                    new RevRepContentBuilder().add(new PKIStatusInfo(PKIStatus.granted)).build());
            return PkiMessageGenerator.generateUnprotectMessage(
                            PkiMessageGenerator.buildRespondingHeaderProvider(request), responseBody)
                    .getEncoded();
        }

        private byte[] certificateResponse(
                final PKIMessage request, final BigInteger certReqId, final byte[] encodedCertificate)
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
            return PkiMessageGenerator.generateUnprotectMessage(
                            PkiMessageGenerator.buildRespondingHeaderProvider(request), responseBody)
                    .getEncoded();
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
