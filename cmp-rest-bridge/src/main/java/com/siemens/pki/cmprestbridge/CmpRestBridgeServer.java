/*
 *  Copyright (c) 2026 Siemens AG
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  SPDX-License-Identifier: Apache-2.0
 */
package com.siemens.pki.cmprestbridge;

import com.siemens.pki.cmprestbridge.config.BridgeConfiguration;
import com.siemens.pki.cmprestbridge.service.CmpRestBridgeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.Base64;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;

/**
 * Main entry point for the CMP-to-REST Bridge server.
 * 
 * This application receives CMP requests from end entities via HTTP/CoAP
 * and forwards them as REST calls to a PKI backend.
 * 
 * Usage:
 *   java -jar CmpRestBridge.jar [config.properties]
 * 
 * Configuration can be provided via:
 * 1. Command-line properties file
 * 2. Environment variables
 * 3. Default values
 */
public class CmpRestBridgeServer {
    
    private static final Logger LOG = LoggerFactory.getLogger(CmpRestBridgeServer.class);
    
    private CmpRestBridgeService bridgeService;
    private BridgeConfiguration config;
    
    public static void main(String[] args) {
        LOG.info("Starting CMP-to-REST Bridge Server...");
        
        try {
            CmpRestBridgeServer server = new CmpRestBridgeServer();
            
            // Load configuration
            BridgeConfiguration config = loadConfiguration(args);
            
            // Initialize bridge service
            server.initialize(config);
            
            LOG.info("CMP-to-REST Bridge Server started successfully");
            LOG.info("Ready to accept CMP requests");
            
            // Keep server running
            synchronized (server) {
                server.wait();
            }
            
        } catch (Exception e) {
            LOG.error("Failed to start server: {}", e.getMessage(), e);
            System.exit(1);
        }
    }
    
    /**
     * Initialize the bridge service with the given configuration.
     */
    public void initialize(BridgeConfiguration config) throws Exception {
        this.config = config;
        this.bridgeService = new CmpRestBridgeService(config);
        LOG.info("Bridge service initialized");
    }
    
    /**
     * Process a CMP request and return the response.
     * Called by the transport layer (HTTP/CoAP server).
     */
    public byte[] processRequest(byte[] cmpRequest) throws Exception {
        if (bridgeService == null) {
            throw new IllegalStateException("Bridge service not initialized");
        }
        return bridgeService.processCmpRequest(cmpRequest);
    }
    
    /**
     * Load configuration from various sources.
     */
    private static BridgeConfiguration loadConfiguration(String[] args) throws IOException {
        Properties props = new Properties();
        
        // Load from file if specified
        if (args.length > 0 && args[0].endsWith(".properties")) {
            try (FileInputStream fis = new FileInputStream(args[0])) {
                props.load(fis);
                LOG.info("Loaded configuration from {}", args[0]);
            }
        }
        
        // Override with environment variables
        loadEnvProperty(props, "REST_API_BASE_URL", "rest.api.base.url");
        loadEnvProperty(props, "CA_NAME", "ca.name");
        loadEnvProperty(props, "REST_API_TOKEN", "rest.api.token");
        loadEnvProperty(props, "DOWNSTREAM_KEYSTORE_PATH", "downstream.keystore.path");
        loadEnvProperty(props, "DOWNSTREAM_KEYSTORE_PASSWORD", "downstream.keystore.password");
        loadEnvProperty(props, "DOWNSTREAM_KEY_ALIAS", "downstream.key.alias");
        loadEnvProperty(props, "DOWNSTREAM_KEY_PASSWORD", "downstream.key.password");
        
        // Build configuration
        BridgeConfiguration.Builder builder = BridgeConfiguration.builder()
            .restApiBaseUrl(props.getProperty("rest.api.base.url", "https://pki.example.com/api"))
            .caName(props.getProperty("ca.name", "defaultCA"))
            .restApiToken(props.getProperty("rest.api.token"))
            .downstreamProtection(props.getProperty("downstream.protection.type", "signature"))
            .downstreamKeystore(
                props.getProperty("downstream.keystore.path"),
                props.getProperty("downstream.keystore.password"),
                props.getProperty("downstream.key.alias"),
                props.getProperty("downstream.key.password")
            )
            .messageTimeDeviationSeconds(Integer.parseInt(
                props.getProperty("message.time.deviation.seconds", "300")))
            .pollingIntervalSeconds(Integer.parseInt(
                props.getProperty("polling.interval.seconds", "30")))
            .defaultValidity(props.getProperty("default.validity", "1y"));
        
        // Load trusted certificates if specified
        String trustedCertsPath = props.getProperty("downstream.trusted.certs.path");
        if (trustedCertsPath != null) {
            builder.downstreamTrustedCerts(loadCertificates(trustedCertsPath));
        }
        
        String enrollmentCertsPath = props.getProperty("enrollment.trusted.certs.path");
        if (enrollmentCertsPath != null) {
            builder.enrollmentTrustedCerts(loadCertificates(enrollmentCertsPath));
        }
        
        return builder.build();
    }
    
    private static void loadEnvProperty(Properties props, String envVar, String propKey) {
        String envValue = System.getenv(envVar);
        if (envValue != null && !envValue.isEmpty()) {
            props.setProperty(propKey, envValue);
        }
    }
    
    private static Collection<X509Certificate> loadCertificates(String path) throws Exception {
        Collection<X509Certificate> certs = new ArrayList<>();
        
        try (FileInputStream fis = new FileInputStream(path)) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            for (X509Certificate cert : (Collection<X509Certificate>) cf.generateCertificates(fis)) {
                certs.add(cert);
            }
        }
        
        LOG.info("Loaded {} certificates from {}", certs.size(), path);
        return certs;
    }
}
