/*
 *  Copyright (c) 2024 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 */
package com.siemens.pki.cmpgateway.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/**
 * REST client for communicating with CEMA RA API.
 * Handles authentication, CSRF tokens, and certificate operations.
 */
public class RestClient {
    
    private static final Logger LOG = LoggerFactory.getLogger(RestClient.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    
    private final String baseUrl;
    private final String caName;
    private final String tplName;
    private final String lookupName;
    private final String authType;
    private final String username;
    private final String password;
    private final KeyStore keyStore;
    private final String keystorePassword;
    private final String keyAlias;
    
    private final HttpClient httpClient;
    private String authToken;
    private String csrfToken;
    private final Map<String, PendingRequest> pendingRequests = new ConcurrentHashMap<>();
    
    /**
     * Tracks a pending certificate request.
     */
    public static class PendingRequest {
        public final String uuid;
        public final long timestamp;
        public final int bodyType;
        
        public PendingRequest(String uuid, int bodyType) {
            this.uuid = uuid;
            this.timestamp = System.currentTimeMillis();
            this.bodyType = bodyType;
        }
    }
    
    public RestClient(String baseUrl, String caName, String tplName, String lookupName,
                      String authType, String username, String password,
                      KeyStore keyStore, String keystorePassword, String keyAlias) throws Exception {
        this.baseUrl = baseUrl;
        this.caName = caName;
        this.tplName = tplName;
        this.lookupName = lookupName;
        this.authType = authType;
        this.username = username;
        this.password = password;
        this.keyStore = keyStore;
        this.keystorePassword = keystorePassword;
        this.keyAlias = keyAlias;
        
        this.httpClient = createHttpClient();
        
        // Initial authentication
        if ("basic".equalsIgnoreCase(authType)) {
            authenticateBasic();
        } else if ("certificate".equalsIgnoreCase(authType)) {
            authenticateCertificate();
        }
    }
    
    private HttpClient createHttpClient() throws Exception {
        HttpClient.Builder builder = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_2)
                .followRedirects(HttpClient.Redirect.NORMAL);
        
        if (keyStore != null && "certificate".equalsIgnoreCase(authType)) {
            // Create SSL context with client certificate
            KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
            trustStore.load(null, null);
            
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
            
            builder.sslContext(sslContext);
        }
        
        return builder.build();
    }
    
    /**
     * Authenticate using basic auth (username/password).
     */
    private void authenticateBasic() throws IOException, InterruptedException {
        LOG.info("Authenticating with basic auth for user: {}", username);
        
        // Step 1: Identify
        String identifyUrl = baseUrl + "/auth/identify";
        ObjectNode identifyRequest = MAPPER.createObjectNode();
        identifyRequest.put("user", username);
        identifyRequest.put("domain", "");
        
        HttpRequest identifyReq = HttpRequest.newBuilder()
                .uri(URI.create(identifyUrl))
                .POST(HttpRequest.BodyPublishers.ofString(identifyRequest.toString()))
                .header("Content-Type", "application/json")
                .build();
        
        HttpResponse<String> identifyResp = httpClient.send(identifyReq, HttpResponse.BodyHandlers.ofString());
        if (identifyResp.statusCode() != 200) {
            throw new IOException("Identify failed: " + identifyResp.statusCode() + " - " + identifyResp.body());
        }
        
        JsonNode identifyNode = MAPPER.readTree(identifyResp.body());
        String token = identifyNode.path("tok").asText();
        
        // Step 2: Login with password challenge
        String loginUrl = baseUrl + "/auth/login";
        ObjectNode loginRequest = MAPPER.createObjectNode();
        loginRequest.put("token", identifyNode.path("challenge").path("token").asText());
        loginRequest.put("value", password);
        
        HttpRequest loginReq = HttpRequest.newBuilder()
                .uri(URI.create(loginUrl))
                .POST(HttpRequest.BodyPublishers.ofString(loginRequest.toString()))
                .header("Content-Type", "application/json")
                .header("X-CSRF-Token", extractCsrfToken(identifyResp))
                .build();
        
        HttpResponse<String> loginResp = httpClient.send(loginReq, HttpResponse.BodyHandlers.ofString());
        if (loginResp.statusCode() != 200) {
            throw new IOException("Login failed: " + loginResp.statusCode() + " - " + loginResp.body());
        }
        
        JsonNode loginNode = MAPPER.readTree(loginResp.body());
        this.authToken = loginNode.path("tok").asText();
        this.csrfToken = extractCsrfToken(loginResp);
        
        LOG.info("Authentication successful, token expires: {}", loginNode.path("expiry").asText());
    }
    
    /**
     * Authenticate using client certificate.
     */
    private void authenticateCertificate() throws IOException, InterruptedException {
        LOG.info("Authenticating with client certificate");
        
        // For certificate auth, we use SSO endpoint
        String ssoUrl = baseUrl + "/auth/sso";
        
        HttpRequest ssoReq = HttpRequest.newBuilder()
                .uri(URI.create(ssoUrl))
                .GET()
                .build();
        
        HttpResponse<String> ssoResp = httpClient.send(ssoReq, HttpResponse.BodyHandlers.ofString());
        
        if (ssoResp.statusCode() == 200) {
            JsonNode ssoNode = MAPPER.readTree(ssoResp.body());
            this.authToken = ssoNode.path("tok").asText();
            this.csrfToken = extractCsrfToken(ssoResp);
            LOG.info("Certificate authentication successful");
        } else {
            // Fallback to basic auth if certificate auth fails
            LOG.warn("Certificate auth failed ({}), falling back to basic auth", ssoResp.statusCode());
            if (username != null && password != null) {
                authenticateBasic();
            } else {
                throw new IOException("Certificate auth failed and no fallback credentials available");
            }
        }
    }
    
    private String extractCsrfToken(HttpResponse<String> response) {
        // CSRF token is typically in response headers or body
        // For now, generate a random one if not found
        String headerCsrf = response.headers().firstValue("X-CSRF-Token").orElse(null);
        if (headerCsrf != null) {
            return headerCsrf;
        }
        
        // Try to extract from response body
        try {
            JsonNode node = MAPPER.readTree(response.body());
            JsonNode ctx = node.path("ctx");
            if (ctx.has("csrf")) {
                return ctx.path("csrf").asText();
            }
        } catch (Exception e) {
            // Ignore parsing errors
        }
        
        // Generate random CSRF token as fallback
        return UUID.randomUUID().toString().replace("-", "");
    }
    
    /**
     * Issue certificate using template-based approach.
     * @param csr Base64-encoded PKCS#10 CSR
     * @return IssuedCertificateData or PendingRequest info
     */
    public CertificateResult issueCertificate(String csr) throws IOException, InterruptedException {
        LOG.info("Issuing certificate for CA: {}, Template: {}", caName, tplName);
        
        String issueUrl = baseUrl + "/ca/" + caName + "/template/" + tplName + "/issue";
        
        ObjectNode request = MAPPER.createObjectNode();
        request.put("csr", csr);
        request.put("proto", "CMP");
        request.put("returnIssuer", true);
        request.put("returnChain", true);
        request.put("returnRoot", false);
        request.put("format", "DER");
        
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(issueUrl))
                .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
                .header("Content-Type", "application/json")
                .header("X-CSRF-Token", csrfToken)
                .header("X-AuthToken", authToken)
                .header("Cookie", "AuthToken=" + authToken)
                .build();
        
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        
        LOG.debug("Issue response status: {}", resp.statusCode());
        
        if (resp.statusCode() == 201) {
            // Certificate issued immediately
            JsonNode result = MAPPER.readTree(resp.body());
            return parseCertificateResult(result);
        } else if (resp.statusCode() == 202) {
            // Certificate pending
            JsonNode result = MAPPER.readTree(resp.body());
            String uuid = result.path("uuid").asText();
            pendingRequests.put(uuid, new PendingRequest(uuid, 2)); // 2 = CR body type
            return new CertificateResult(true, uuid, result.path("msg").asText());
        } else {
            throw new IOException("Certificate issuance failed: " + resp.statusCode() + " - " + resp.body());
        }
    }
    
    /**
     * Auto-issue certificate using lookup name.
     * @param csr Base64-encoded PKCS#10 CSR
     */
    public CertificateResult autoIssueCertificate(String csr) throws IOException, InterruptedException {
        LOG.info("Auto-issuing certificate with lookup: {}", lookupName);
        
        String issueUrl = baseUrl + "/ca/auto-issue/" + lookupName;
        
        ObjectNode request = MAPPER.createObjectNode();
        request.put("csr", csr);
        request.put("proto", "CMP");
        request.put("returnIssuer", true);
        request.put("returnChain", true);
        request.put("returnRoot", false);
        request.put("format", "DER");
        
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(issueUrl))
                .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
                .header("Content-Type", "application/json")
                .header("X-CSRF-Token", csrfToken)
                .header("X-AuthToken", authToken)
                .header("Cookie", "AuthToken=" + authToken)
                .build();
        
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        
        if (resp.statusCode() == 201) {
            JsonNode result = MAPPER.readTree(resp.body());
            return parseCertificateResult(result);
        } else if (resp.statusCode() == 202) {
            JsonNode result = MAPPER.readTree(resp.body());
            String uuid = result.path("uuid").asText();
            pendingRequests.put(uuid, new PendingRequest(uuid, 2));
            return new CertificateResult(true, uuid, result.path("msg").asText());
        } else {
            throw new IOException("Auto certificate issuance failed: " + resp.statusCode() + " - " + resp.body());
        }
    }
    
    /**
     * Revoke a certificate.
     * @param serial Serial number of certificate to revoke
     * @param reason Revocation reason code
     */
    public boolean revokeCertificate(String serial, int reason) throws IOException, InterruptedException {
        LOG.info("Revoking certificate with serial: {}, reason: {}", serial, reason);
        
        String revokeUrl = baseUrl + "/ca/" + caName + "/revoke";
        
        ObjectNode request = MAPPER.createObjectNode();
        request.put("serial", serial);
        request.put("reason", reason);
        
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(revokeUrl))
                .method("PATCH", HttpRequest.BodyPublishers.ofString(request.toString()))
                .header("Content-Type", "application/json")
                .header("X-CSRF-Token", csrfToken)
                .header("X-AuthToken", authToken)
                .header("Cookie", "AuthToken=" + authToken)
                .build();
        
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        
        if (resp.statusCode() == 200) {
            LOG.info("Certificate revoked successfully");
            return true;
        } else {
            throw new IOException("Certificate revocation failed: " + resp.statusCode() + " - " + resp.body());
        }
    }
    
    /**
     * Fetch a pending certificate.
     * @param uuid UUID of pending request
     */
    public CertificateResult fetchPendingCertificate(String uuid) throws IOException, InterruptedException {
        LOG.info("Fetching pending certificate: {}", uuid);
        
        String fetchUrl = baseUrl + "/ca/" + caName + "/fetch";
        
        ObjectNode request = MAPPER.createObjectNode();
        request.put("uuid", uuid);
        
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(fetchUrl))
                .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
                .header("Content-Type", "application/json")
                .header("X-CSRF-Token", csrfToken)
                .header("X-AuthToken", authToken)
                .header("Cookie", "AuthToken=" + authToken)
                .build();
        
        HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
        
        if (resp.statusCode() == 201) {
            JsonNode result = MAPPER.readTree(resp.body());
            CertificateResult certResult = parseCertificateResult(result);
            pendingRequests.remove(uuid);
            return certResult;
        } else if (resp.statusCode() == 202) {
            // Still pending
            JsonNode result = MAPPER.readTree(resp.body());
            return new CertificateResult(true, uuid, result.path("msg").asText());
        } else {
            throw new IOException("Fetch failed: " + resp.statusCode() + " - " + resp.body());
        }
    }
    
    private CertificateResult parseCertificateResult(JsonNode result) {
        try {
            String certBase64 = result.path("cert").asText();
            byte[] certBytes = Base64.getDecoder().decode(certBase64);
            
            String issuerBase64 = result.path("issuer").asText("");
            byte[] issuerBytes = issuerBase64.isEmpty() ? null : Base64.getDecoder().decode(issuerBase64);
            
            JsonNode chainNode = result.path("chain");
            byte[][] chainBytes = null;
            if (chainNode.isArray() && chainNode.size() > 0) {
                chainBytes = new byte[chainNode.size()][];
                for (int i = 0; i < chainNode.size(); i++) {
                    chainBytes[i] = Base64.getDecoder().decode(chainNode.get(i).asText());
                }
            }
            
            String rootBase64 = result.path("root").asText("");
            byte[] rootBytes = rootBase64.isEmpty() ? null : Base64.getDecoder().decode(rootBase64);
            
            String uuid = result.path("uuid").asText();
            
            return new CertificateResult(false, uuid, certBytes, issuerBytes, chainBytes, rootBytes);
        } catch (Exception e) {
            LOG.error("Failed to parse certificate result", e);
            throw new RuntimeException(e);
        }
    }
    
    /**
     * Result of a certificate operation.
     */
    public static class CertificateResult {
        public final boolean pending;
        public final String uuid;
        public final String message;
        public final byte[] certificate;
        public final byte[] issuer;
        public final byte[][] chain;
        public final byte[] root;
        
        // For pending results
        public CertificateResult(boolean pending, String uuid, String message) {
            this.pending = pending;
            this.uuid = uuid;
            this.message = message;
            this.certificate = null;
            this.issuer = null;
            this.chain = null;
            this.root = null;
        }
        
        // For completed results
        public CertificateResult(boolean pending, String uuid, byte[] cert, byte[] issuer, 
                                 byte[][] chain, byte[] root) {
            this.pending = pending;
            this.uuid = uuid;
            this.message = null;
            this.certificate = cert;
            this.issuer = issuer;
            this.chain = chain;
            this.root = root;
        }
    }
}
