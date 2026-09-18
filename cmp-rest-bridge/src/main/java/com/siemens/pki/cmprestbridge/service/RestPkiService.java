package com.siemens.pki.cmprestbridge.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.siemens.pki.cmprestbridge.model.CertificateRequestSign;
import com.siemens.pki.cmprestbridge.model.IssuedCertificateData;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Service for communicating with the REST-based PKI backend.
 * This class handles all HTTP/REST interactions with the CA system.
 */
public class RestPkiService {
    
    private static final Logger LOG = LoggerFactory.getLogger(RestPkiService.class);
    
    private final String baseUrl;
    private final String caName;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final String authToken;

    /**
     * Create a new REST PKI service.
     *
     * @param baseUrl   Base URL of the REST API (e.g., "https://pki.example.com/api")
     * @param caName    Name of the CA to use for certificate issuance
     * @param authToken Optional authentication token for API calls
     */
    public RestPkiService(String baseUrl, String caName, String authToken) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.caName = caName;
        this.authToken = authToken;
        this.httpClient = HttpClient.newHttpClient();
        this.objectMapper = new ObjectMapper();
        LOG.info("RestPkiService initialized with baseUrl={}, caName={}", this.baseUrl, caName);
    }

    /**
     * Issue a certificate using the REST API.
     * This is called when the CMP RA component processes a certificate request.
     *
     * @param csrBytes DER-encoded PKCS#10 certificate signing request
     * @param commonName Common name for the certificate (optional)
     * @param validity Validity period (e.g., "1y", "365d")
     * @return DER-encoded certificate bytes
     * @throws Exception on error
     */
    public byte[] issueCertificate(byte[] csrBytes, String commonName, String validity) throws Exception {
        LOG.debug("Issuing certificate via REST API");
        
        // Convert CSR to Base64
        String csrBase64 = Base64.getEncoder().encodeToString(csrBytes);
        
        // Build request payload
        CertificateRequestSign request = new CertificateRequestSign();
        request.setCsr(csrBase64);
        request.setCommonName(commonName);
        request.setValidity(validity != null ? validity : "1y");
        request.setProto("CMP");
        request.setReturnIssuer(true);
        request.setReturnChain(true);
        request.setReturnRoot(false);
        request.setFormat("DER");
        
        String jsonPayload = objectMapper.writeValueAsString(request);
        LOG.trace("REST request payload: {}", jsonPayload);
        
        // Make HTTP POST request
        String endpoint = baseUrl + "/ca/" + encodePath(caName) + "/auto-issue";
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(jsonPayload))
                .build();
        
        addAuthHeader(httpRequest);
        
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200 && response.statusCode() != 201) {
            throw new IOException("REST API returned status " + response.statusCode() + ": " + response.body());
        }
        
        // Parse response
        IssuedCertificateData certData = objectMapper.readValue(response.body(), IssuedCertificateData.class);
        
        if (certData.getCert() == null || certData.getCert().isEmpty()) {
            throw new IOException("No certificate returned from REST API");
        }
        
        // Decode Base64 certificate to DER
        byte[] certDer = Base64.getDecoder().decode(certData.getCert());
        LOG.info("Successfully issued certificate with UUID={}", certData.getUuid());
        
        return certDer;
    }

    /**
     * Get the CA certificate chain from the REST API.
     *
     * @return PEM-encoded certificate chain
     * @throws Exception on error
     */
    public String getCACertificateChain() throws Exception {
        LOG.debug("Fetching CA certificate chain");
        
        String endpoint = baseUrl + "/ca/" + encodePath(caName) + "/chain";
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Accept", "application/x-pem-file")
                .GET()
                .build();
        
        addAuthHeader(httpRequest);
        
        HttpResponse<String> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
        
        if (response.statusCode() != 200) {
            throw new IOException("REST API returned status " + response.statusCode() + ": " + response.body());
        }
        
        LOG.info("Successfully fetched CA certificate chain");
        return response.body();
    }

    /**
     * Get the CA certificate from the REST API.
     *
     * @return DER-encoded CA certificate
     * @throws Exception on error
     */
    public byte[] getCACertificate() throws Exception {
        LOG.debug("Fetching CA certificate");
        
        String endpoint = baseUrl + "/ca/" + encodePath(caName) + "/cert";
        HttpRequest httpRequest = HttpRequest.newBuilder()
                .uri(URI.create(endpoint))
                .header("Accept", "application/pkix-cert")
                .GET()
                .build();
        
        addAuthHeader(httpRequest);
        
        HttpResponse<byte[]> response = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
        
        if (response.statusCode() != 200) {
            throw new IOException("REST API returned status " + response.statusCode());
        }
        
        LOG.info("Successfully fetched CA certificate");
        return response.body();
    }

    private void addAuthHeader(HttpRequest request) {
        if (authToken != null && !authToken.isEmpty()) {
            // Note: In real implementation, you'd need to use reflection or builder pattern
            // to add headers after request creation. For now, this is a placeholder.
            LOG.debug("Authentication token configured");
        }
    }

    private String encodePath(String path) {
        try {
            return URLEncoder.encode(path, StandardCharsets.UTF_8.toString());
        } catch (Exception e) {
            return path;
        }
    }

    /**
     * Placeholder for URI encoder - in real code use java.net.URLEncoder
     */
    private static String URLEncoder_encode(String s, String encoding) throws java.io.UnsupportedEncodingException {
        return java.net.URLEncoder.encode(s, encoding);
    }
}
