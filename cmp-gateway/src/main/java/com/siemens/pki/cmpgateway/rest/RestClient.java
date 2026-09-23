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
import java.net.HttpCookie;
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
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import javax.net.ssl.SSLContext;
import javax.net.ssl.KeyManagerFactory;
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
    private final KeyStore trustStore;
    
    private final HttpClient httpClient;
    private String authToken;
    private String csrfToken;
    // Session cookies received from CEMA (e.g. the AuthToken cookie), sent back on every request
    private final Map<String, String> sessionCookies = new ConcurrentHashMap<>();
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
                      KeyStore keyStore, String keystorePassword, String keyAlias,
                      KeyStore trustStore) throws Exception {
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
        this.trustStore = trustStore;
        
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
        
        if ((keyStore != null && "certificate".equalsIgnoreCase(authType)) || trustStore != null) {
            javax.net.ssl.KeyManager[] keyManagers = null;
            if (keyStore != null && "certificate".equalsIgnoreCase(authType)) {
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                        KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, keystorePassword.toCharArray());
                keyManagers = kmf.getKeyManagers();
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                    TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(trustStore);
            
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, tmf.getTrustManagers(), new SecureRandom());
            
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
        for (String setCookie : identifyResp.headers().allValues("Set-Cookie")) {
            storeCookies(setCookie);
        }
        
        // Step 2: Complete the login (POST /auth/login) answering the password challenge
        completeLogin(identifyResp, password);
    }
    
    /**
     * Authenticate using client certificate.
     * Flow: POST /auth/identify -> (if not already authenticated by the cert) POST /auth/login.
     */
    private void authenticateCertificate() throws IOException, InterruptedException {
        LOG.info("Authenticating with client certificate");

        // Step 1: Identify the user (POST /auth/identify). The TLS client certificate presented
        // during the handshake maps to this user on the server side.
        String identifyUrl = baseUrl + "/auth/identify";
        ObjectNode identifyRequest = MAPPER.createObjectNode();
        identifyRequest.put("user", username != null && !username.isBlank() ? username : "TenantAdmin");
        identifyRequest.put("domain", "");

        HttpRequest identifyReq = HttpRequest.newBuilder()
                .uri(URI.create(identifyUrl))
                .POST(HttpRequest.BodyPublishers.ofString(identifyRequest.toString()))
                .header("Content-Type", "application/json")
                .build();

        HttpResponse<String> identifyResp = httpClient.send(identifyReq, HttpResponse.BodyHandlers.ofString());

        // Store any cookies; CEMA sets session cookies already at this stage.
        for (String setCookie : identifyResp.headers().allValues("Set-Cookie")) {
            storeCookies(setCookie);
        }

        // If the client certificate was accepted, /auth/identify may return a completed
        // AuthResponse directly (AuthToken cookie set) instead of a password challenge.
        if (identifyResp.statusCode() == 200) {
            JsonNode identifyNode = readJsonOrEmpty(identifyResp.body());
            String cookieToken = sessionCookies.get("authtoken");
            boolean haveSession = cookieToken != null && !cookieToken.isBlank();
            boolean certAccepted = haveSession
                    || ("success".equalsIgnoreCase(identifyNode.path("ctx").path("status").asText("")));
            if (certAccepted) {
                this.authToken = extractAuthToken(identifyResp, identifyNode);
                this.csrfToken = extractCsrfToken(identifyResp);
                LOG.info("Certificate authentication successful via /auth/identify");
                return;
            }
        }

        // Step 2: Complete the login (POST /auth/login) answering the challenge from identify.
        // With certificate auth there is no password value to supply, so the challenge token is
        // echoed back with an empty value.
        LOG.info("Certificate auth requires login step, calling /auth/login");
        completeLogin(identifyResp, "");
    }

    /**
     * Complete a two-step login: POST /auth/login answering the challenge returned by a previous
     * /auth/identify response. Shared by the basic-auth and certificate-auth flows.
     */
    private void completeLogin(final HttpResponse<String> identifyResp, final String credentialValue)
            throws IOException, InterruptedException {
        JsonNode identifyNode = readJsonOrEmpty(identifyResp.body());

        String loginUrl = baseUrl + "/auth/login";
        ObjectNode loginRequest = MAPPER.createObjectNode();
        loginRequest.put("token", identifyNode.path("challenge").path("token").asText(""));
        loginRequest.put("value", credentialValue);

        HttpRequest.Builder loginBuilder = HttpRequest.newBuilder()
                .uri(URI.create(loginUrl))
                .POST(HttpRequest.BodyPublishers.ofString(loginRequest.toString()))
                .header("Content-Type", "application/json");
        // The CSRF token and Cookie header may legitimately be absent (e.g. the very first
        // login has no session cookies yet, and some CEMA configurations do not send
        // X-CSRF-Token on every auth response). HttpRequest.Builder.header() rejects null
        // values with a NullPointerException, so only add headers that actually have a value.
        String csrf = extractCsrfToken(identifyResp);
        if (csrf != null && !csrf.isBlank()) {
            loginBuilder.header("X-CSRF-Token", csrf);
        }
        addCookieHeader(loginBuilder);
        HttpRequest loginReq = loginBuilder.build();

        HttpResponse<String> loginResp = httpClient.send(loginReq, HttpResponse.BodyHandlers.ofString());
        for (String setCookie : loginResp.headers().allValues("Set-Cookie")) {
            storeCookies(setCookie);
        }

        JsonNode loginNode = readJsonOrEmpty(loginResp.body());
        if (loginResp.statusCode() != 200) {
            throw new IOException("Login failed: HTTP " + loginResp.statusCode()
                    + " - " + abbreviate(loginResp.body()));
        }

        // The actual AuthToken is delivered as Set-Cookie ("tok" in the body is a placeholder)
        this.authToken = extractAuthToken(loginResp, loginNode);
        this.csrfToken = extractCsrfToken(loginResp);

        LOG.info("Authentication successful, token expires: {}", loginNode.path("expiry").asText("unknown"));
    }

    /**
     * Parse a JSON body, returning an empty object node if the body is not valid JSON
     * (e.g. an HTML error page).
     */
    private JsonNode readJsonOrEmpty(final String body) {
        try {
            JsonNode node = MAPPER.readTree(body);
            return node != null ? node : MAPPER.createObjectNode();
        } catch (Exception e) {
            return MAPPER.createObjectNode();
        }
    }

    private String extractAuthToken(
            final HttpResponse<String> response, final JsonNode responseBody) {
        // Per the CEMA OpenAPI spec (AuthResponse), the "tok" field in the JSON body is only
        // a placeholder; the actual authentication token is delivered in the AuthToken cookie.
        // So the Set-Cookie header takes precedence over the body value.
        for (String setCookie : response.headers().allValues("Set-Cookie")) {
            storeCookies(setCookie);
        }
        String cookieToken = sessionCookies.get("authtoken");
        if (cookieToken != null && !cookieToken.isBlank()) {
            return cookieToken;
        }
        // Fall back to the body value if no cookie was supplied
        final String bodyToken = responseBody.path("tok").asText(null);
        if (bodyToken != null && !bodyToken.isBlank()) {
            return bodyToken;
        }
        throw new IllegalStateException("CEMA authentication response did not contain an AuthToken"
                + " (HTTP " + response.statusCode() + ", body: " + abbreviate(response.body()) + ")");
    }

    /**
     * Parse a Set-Cookie header value and remember the cookie for subsequent requests.
     */
    private void storeCookies(String setCookieHeader) {
        try {
            for (HttpCookie cookie : HttpCookie.parse(setCookieHeader)) {
                if (cookie.hasExpired() || cookie.getMaxAge() == 0) {
                    sessionCookies.remove(cookie.getName().toLowerCase());
                } else {
                    sessionCookies.put(cookie.getName().toLowerCase(), cookie.getValue());
                }
            }
        } catch (IllegalArgumentException e) {
            LOG.debug("Ignoring unparsable Set-Cookie header: {}", setCookieHeader);
        }
    }

    /**
     * Build the Cookie header from all cookies received so far, ensuring that the
     * AuthToken cookie is present even when only a token value is known.
     */
    private String buildCookieHeader() {
        StringBuilder sb = new StringBuilder();
        String token = authToken;
        if (token != null && !token.isBlank()) {
            sb.append("AuthToken=").append(token);
        }
        for (Map.Entry<String, String> entry : sessionCookies.entrySet()) {
            if ("authtoken".equals(entry.getKey())) {
                continue; // already added above if non-blank
            }
            if (sb.length() > 0) {
                sb.append("; ");
            }
            sb.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    /**
     * Add the Cookie header to a request builder, but only if there are any cookies to send.
     * HttpRequest.Builder.header() throws a NullPointerException on null values, and the very
     * first requests (e.g. /auth/login before any session cookie exists) legitimately have none.
     */
    private HttpRequest.Builder addCookieHeader(final HttpRequest.Builder builder) {
        String cookieHeader = buildCookieHeader();
        if (cookieHeader != null && !cookieHeader.isBlank()) {
            builder.header("Cookie", cookieHeader);
        }
        return builder;
    }

    /**
     * Add the authentication headers (X-CSRF-Token, X-AuthToken, Cookie) that are present after
     * a successful login. Headers without a value are omitted instead of being passed as null,
     * which would make HttpRequest.Builder.header() throw a NullPointerException.
     */
    private HttpRequest.Builder addAuthHeaders(final HttpRequest.Builder builder) {
        String csrf = this.csrfToken;
        if (csrf != null && !csrf.isBlank()) {
            builder.header("X-CSRF-Token", csrf);
        }
        String token = this.authToken;
        if (token != null && !token.isBlank()) {
            builder.header("X-AuthToken", token);
        }
        return addCookieHeader(builder);
    }

    private static String abbreviate(String s) {
        if (s == null) {
            return "null";
        }
        return s.length() > 200 ? s.substring(0, 200) + "..." : s;
    }
    
    private String extractCsrfToken(HttpResponse<String> response) {
        // Per the CEMA OpenAPI spec (AuthResponse), the CSRF token for subsequent requests is
        // returned in the X-CSRF-Token response header.
        String headerCsrf = response.headers().firstValue("X-CSRF-Token").orElse(null);
        if (headerCsrf != null && !headerCsrf.isBlank()) {
            this.csrfToken = headerCsrf;
            return headerCsrf;
        }

        // Fall back to any previously received CSRF token: per the spec, "any previously received
        // token will be acceptable, as long as it was received from the same server and has not
        // yet expired". If we never received one at all, proceed without it rather than failing
        // startup (some CEMA configurations do not send X-CSRF-Token on every auth response).
        return this.csrfToken;
    }

    private String requireCsrfToken(HttpResponse<String> response) {
        String csrf = extractCsrfToken(response);
        if (csrf == null || csrf.isBlank()) {
            throw new IllegalStateException("CEMA response did not contain a CSRF token"
                    + " (HTTP " + response.statusCode() + ", body: " + abbreviate(response.body()) + ")");
        }
        return csrf;
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
        
        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(issueUrl))
                .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
                .header("Content-Type", "application/json");
        HttpRequest req = addAuthHeaders(reqBuilder).build();
        
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
     * Generate a key pair in CEMA and issue its certificate.
     */
    public CertificateResult generateCertificate(
                final String kind, final Integer size, final String ecCurve, final String commonName)
                throws IOException, InterruptedException {
            String generateUrl = baseUrl + "/ca/" + caName + "/template/" + tplName + "/generate";
            ObjectNode request = MAPPER.createObjectNode();
            request.put("kind", kind);
            if (size != null) {
                request.put("size", size);
            }
            if (ecCurve != null && !ecCurve.isBlank()) {
                request.put("ecCurve", ecCurve);
            }
            if (commonName != null && !commonName.isBlank()) {
                request.put("commonName", commonName);
            }
            request.put("proto", "CMP");
            request.put("returnIssuer", true);
            request.put("returnChain", true);
            request.put("returnRoot", false);
            request.put("format", "DER");

            HttpRequest.Builder httpRequestBuilder = HttpRequest.newBuilder()
                    .uri(URI.create(generateUrl))
                    .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
                    .header("Content-Type", "application/json");
            HttpRequest httpRequest = addAuthHeaders(httpRequestBuilder).build();
            HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 201) {
                return parseCertificateResult(MAPPER.readTree(response.body()));
            }
            if (response.statusCode() == 202) {
                JsonNode result = MAPPER.readTree(response.body());
                String uuid = result.path("uuid").asText();
                pendingRequests.put(uuid, new PendingRequest(uuid, 0));
                return new CertificateResult(true, uuid, result.path("msg").asText());
            }
            throw new IOException("Key generation failed: " + response.statusCode() + " - " + response.body());
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
        
        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(issueUrl))
                .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
                .header("Content-Type", "application/json");
        HttpRequest req = addAuthHeaders(reqBuilder).build();
        
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
        
        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(revokeUrl))
                .method("PATCH", HttpRequest.BodyPublishers.ofString(request.toString()))
                .header("Content-Type", "application/json");
        HttpRequest req = addAuthHeaders(reqBuilder).build();
        
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
        
        HttpRequest.Builder reqBuilder = HttpRequest.newBuilder()
                .uri(URI.create(fetchUrl))
                .POST(HttpRequest.BodyPublishers.ofString(request.toString()))
                .header("Content-Type", "application/json");
        HttpRequest req = addAuthHeaders(reqBuilder).build();
        
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
            String keyBase64 = result.path("key").asText("");
            byte[] keyBytes = keyBase64.isEmpty() ? null : Base64.getDecoder().decode(keyBase64);
            
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
            
            return new CertificateResult(false, uuid, keyBytes, certBytes, issuerBytes, chainBytes, rootBytes);
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
        public final byte[] privateKey;
        public final byte[] issuer;
        public final byte[][] chain;
        public final byte[] root;
        
        // For pending results
        public CertificateResult(boolean pending, String uuid, String message) {
            this.pending = pending;
            this.uuid = uuid;
            this.message = message;
            this.certificate = null;
            this.privateKey = null;
            this.issuer = null;
            this.chain = null;
            this.root = null;
        }
        
        // For completed results
        public CertificateResult(boolean pending, String uuid, byte[] key, byte[] cert, byte[] issuer,
                                 byte[][] chain, byte[] root) {
            this.pending = pending;
            this.uuid = uuid;
            this.message = null;
            this.certificate = cert;
            this.privateKey = key;
            this.issuer = issuer;
            this.chain = chain;
            this.root = root;
        }
    }
}
