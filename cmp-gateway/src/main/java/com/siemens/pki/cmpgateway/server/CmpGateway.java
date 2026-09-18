/*
 *  Copyright (c) 2024 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 */
package com.siemens.pki.cmpgateway.server;

import com.siemens.pki.cmpracomponent.main.CmpRaComponent;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.CmpRaInterface;
import com.siemens.pki.cmpracomponent.main.CmpRaComponent.UpstreamExchange;
import com.siemens.pki.cmpgateway.config.GatewayConfig;
import com.siemens.pki.cmpgateway.rest.RestClient;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.RevReqContent;
import org.bouncycastle.asn1.pkcs.RevDetails;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

/**
 * Main gateway application that receives CMP requests and forwards to REST API.
 * Uses cmp-ra-component for all CMP message processing per RFC 9483.
 */
public class CmpGateway {
    
    private static final Logger LOG = LoggerFactory.getLogger(CmpGateway.class);
    
    private final GatewayConfig config;
    private final RestClient restClient;
    private final CmpRaInterface cmpRaInterface;
    private final HttpServer httpServer;
    private final ExecutorService executor;
    
    public CmpGateway(GatewayConfig config) throws Exception {
        this.config = config;
        this.executor = Executors.newFixedThreadPool(10);
        
        // Create REST client
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
            config.getKeyAlias()
        );
        
        // Create CMP RA component - handles all CMP parsing/generation
        this.cmpRaInterface = CmpRaComponent.instantiateCmpRaComponent(
            config,
            new RestApiUpstreamExchange()
        );
        
        // Create HTTP server for CMP endpoint
        int port = 9000;
        this.httpServer = HttpServer.create(new InetSocketAddress(port), 0);
        httpServer.createContext("/cmp", new CmpHandler());
        httpServer.setExecutor(executor);
        
        LOG.info("CMP Gateway initialized on port {}", port);
    }
    
    /**
     * UpstreamExchange implementation - translates CMP to REST and back.
     * The cmp-ra-component handles all CMP message parsing/generation.
     */
    private class RestApiUpstreamExchange implements UpstreamExchange {
        
        @Override
        public byte[] sendReceiveMessage(byte[] cmpRequest, String certProfile, int bodyType) throws Exception {
            LOG.info("Processing CMP request: bodyType={}, profile={}", bodyType, certProfile);
            
            try {
                switch (bodyType) {
                    case 0: // ir
                    case 2: // cr
                    case 7: // kur
                        return handleEnrollment(cmpRequest, bodyType);
                    
                    case 11: // p10cr
                        return handleP10CR(cmpRequest);
                    
                    case 14: // rr (RFC 4210 body type for revocation)
                        return handleRevocation(cmpRequest);
                    
                    case 5: // poll
                        return handlePoll(cmpRequest);
                    
                    default:
                        LOG.warn("Unsupported body type: {}", bodyType);
                        throw new Exception("Unsupported CMP body type: " + bodyType);
                }
            } catch (Exception e) {
                LOG.error("Upstream exchange failed", e);
                throw e;
            }
        }
        
        private byte[] handleEnrollment(byte[] cmpRequest, int bodyType) throws Exception {
            String csrBase64 = extractCsrAsBase64(cmpRequest, bodyType);
            
            RestClient.CertificateResult result = config.getLookupName() != null 
                ? restClient.autoIssueCertificate(csrBase64)
                : restClient.issueCertificate(csrBase64);
            
            if (result.pending) {
                LOG.info("Certificate pending: {}", result.uuid);
                return null; // Triggers polling
            }
            
            // Return certificate bytes - cmp-ra-component builds proper CMP response
            return result.certificate;
        }
        
        private byte[] handleP10CR(byte[] cmpRequest) throws Exception {
            String csrBase64 = extractP10CsrAsBase64(cmpRequest);
            
            RestClient.CertificateResult result = config.getLookupName() != null 
                ? restClient.autoIssueCertificate(csrBase64)
                : restClient.issueCertificate(csrBase64);
            
            if (result.pending) {
                LOG.info("Certificate pending: {}", result.uuid);
                return null;
            }
            
            return result.certificate;
        }
        
        private byte[] handleRevocation(byte[] cmpRequest) throws Exception {
            String serial = extractSerialFromRevocation(cmpRequest);
            restClient.revokeCertificate(serial, 0);
            return new byte[0]; // cmp-ra-component builds RP response
        }
        
        private byte[] handlePoll(byte[] cmpRequest) throws Exception {
            String uuid = extractTransactionId(cmpRequest);
            RestClient.CertificateResult result = restClient.fetchPendingCertificate(uuid);
            
            if (result.pending) {
                return null; // Continue polling
            }
            
            return result.certificate;
        }
        
        private String extractCsrAsBase64(byte[] cmpRequest, int bodyType) throws Exception {
            try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(cmpRequest))) {
                ASN1Primitive primitive = ais.readObject();
                
                if (primitive instanceof CertReqMessages) {
                    CertReqMessages msgs = (CertReqMessages) primitive;
                    CertReqMsg[] reqMsgs = msgs.toCertReqMsgArray();
                    if (reqMsgs != null && reqMsgs.length > 0) {
                        CertRequest certReq = reqMsgs[0].getCertReq();
                        // Get encoded cert request as Base64
                        return Base64.getEncoder().encodeToString(certReq.getEncoded());
                    }
                }
            }
            throw new IOException("Failed to extract CSR from CMP request");
        }
        
        private String extractP10CsrAsBase64(byte[] cmpRequest) throws Exception {
            try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(cmpRequest))) {
                ASN1Primitive primitive = ais.readObject();
                
                if (primitive instanceof CertificationRequest) {
                    PKCS10CertificationRequest p10 = new PKCS10CertificationRequest((CertificationRequest) primitive);
                    return Base64.getEncoder().encodeToString(p10.getEncoded());
                }
            }
            throw new IOException("Failed to extract PKCS#10 CSR from CMP request");
        }
        
        private String extractSerialFromRevocation(byte[] cmpRequest) throws Exception {
            try (ASN1InputStream ais = new ASN1InputStream(new ByteArrayInputStream(cmpRequest))) {
                ASN1Primitive primitive = ais.readObject();
                
                if (primitive instanceof RevReqContent) {
                    RevReqContent content = (RevReqContent) primitive;
                    RevDetails[] details = content.toRevDetailsArray();
                    if (details != null && details.length > 0) {
                        // Extract serial from CertTemplate
                        String serial = details[0].getCertDetails().getSerialNumber().toString();
                        return serial;
                    }
                }
            }
            throw new IOException("Failed to extract serial from revocation request");
        }
        
        private String extractTransactionId(byte[] cmpRequest) throws Exception {
            // For now, use a simple approach - in production would parse PollReq properly
            // Transaction ID is stored in cmp-ra-component's persistency
            // Return empty string as placeholder
            return "";
        }
    }
    
    private class CmpHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws java.io.IOException {
            try {
                if (!"POST".equals(exchange.getRequestMethod())) {
                    exchange.sendResponseHeaders(405, -1);
                    return;
                }
                
                byte[] requestBytes = exchange.getRequestBody().readAllBytes();
                byte[] responseBytes = cmpRaInterface.processRequest(requestBytes);
                
                if (responseBytes == null) {
                    exchange.sendResponseHeaders(200, -1); // Polling required
                } else {
                    exchange.getResponseHeaders().set("Content-Type", "application/pkixcmp");
                    exchange.sendResponseHeaders(200, responseBytes.length);
                    exchange.getResponseBody().write(responseBytes);
                }
                exchange.close();
            } catch (Exception e) {
                LOG.error("CMP request failed", e);
                byte[] errorBytes = ("Error: " + e.getMessage()).getBytes(StandardCharsets.UTF_8);
                exchange.sendResponseHeaders(500, errorBytes.length);
                exchange.getResponseBody().write(errorBytes);
                exchange.close();
            }
        }
    }
    
    public void start() {
        httpServer.start();
        LOG.info("CMP Gateway started on port {}", httpServer.getAddress().getPort());
    }
    
    public void stop() {
        httpServer.stop(5);
        executor.shutdown();
        LOG.info("CMP Gateway stopped");
    }
    
    public static void main(String[] args) throws Exception {
        GatewayConfig config = new GatewayConfig();
        if (args.length > 0) config.setRestBaseUrl(args[0]);
        if (args.length > 1) config.setCaName(args[1]);
        if (args.length > 2) config.setTplName(args[2]);
        
        CmpGateway gateway = new CmpGateway(config);
        gateway.start();
        Runtime.getRuntime().addShutdownHook(new Thread(gateway::stop));
        Thread.currentThread().join();
    }
}
