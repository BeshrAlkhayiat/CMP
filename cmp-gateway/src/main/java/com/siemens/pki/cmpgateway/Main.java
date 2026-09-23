/*
 *  Copyright (c) 2024 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 */
package com.siemens.pki.cmpgateway;

import com.siemens.pki.cmpgateway.config.GatewayConfig;
import com.siemens.pki.cmpgateway.server.CmpGateway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

/**
 * Main entry point for CMP Gateway application.
 * Starts the gateway server that receives CMP requests and forwards them to REST API.
 */
public class Main {
    
    private static final Logger LOG = LoggerFactory.getLogger(Main.class);
    
    public static void main(String[] args) {
        LOG.info("Starting CMP Gateway...");
        
        try {
            // Load configuration
            GatewayConfig config = loadConfiguration(args);
            
            // Create and start gateway
            CmpGateway gateway = new CmpGateway(config);
            gateway.start();
            
            // Add shutdown hook
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                LOG.info("Shutting down CMP Gateway...");
                gateway.stop();
            }));
            
            LOG.info("CMP Gateway started successfully. Listening on port 9000 at /cmp");
            LOG.info("Press Ctrl+C to stop");
            
            // Keep running
            Thread.currentThread().join();
            
        } catch (Exception e) {
            LOG.error("Failed to start CMP Gateway", e);
            System.exit(1);
        }
    }
    
    /**
     * Load configuration from properties file or command line arguments.
     */
    private static GatewayConfig loadConfiguration(String[] args) throws IOException {
        GatewayConfig config = new GatewayConfig();
        
        // Try to load from properties file first
        Properties props = new Properties();
        String configPath = System.getProperty("config.file", "gateway.properties");
        
        try (FileInputStream fis = new FileInputStream(configPath)) {
            props.load(fis);
            
            config.setRestBaseUrl(props.getProperty("rest.baseUrl", config.getRestBaseUrl()));
            config.setCaName(props.getProperty("ca.name", config.getCaName()));
            config.setTplName(props.getProperty("template.name", config.getTplName()));
            config.setLookupName(props.getProperty("lookup.name", config.getLookupName()));
            config.setAuthType(props.getProperty("auth.type", config.getAuthType()));
            config.setUsername(props.getProperty("auth.username", config.getUsername()));
            config.setPassword(props.getProperty("auth.password", config.getPassword()));
            config.setLoginUser(props.getProperty("auth.login.user", config.getLoginUser()));
            config.setKeystorePath(props.getProperty("auth.keystore.path", config.getKeystorePath()));
            config.setKeystorePassword(props.getProperty("auth.keystore.password", config.getKeystorePassword()));
            config.setKeyAlias(props.getProperty("auth.keystore.alias", config.getKeyAlias()));
            config.setTruststorePath(props.getProperty("auth.truststore.path", config.getTruststorePath()));
            config.setTruststorePassword(
                    props.getProperty("auth.truststore.password", config.getTruststorePassword()));
            config.setTruststoreType(props.getProperty("auth.truststore.type", config.getTruststoreType()));
            
            String secret = props.getProperty("cmp.protection.secret", null);
            if (secret != null) {
                config.setSharedSecret(secret.getBytes());
            }
            
            config.setRetryAfterSeconds(Integer.parseInt(
                props.getProperty("retry.after.seconds", String.valueOf(config.getRetryAfterSeconds()))));
            config.setDownstreamTimeoutSeconds(Integer.parseInt(
                props.getProperty("downstream.timeout.seconds", String.valueOf(config.getDownstreamTimeoutSeconds()))));
            config.setCmpPort(Integer.parseInt(
                props.getProperty("cmp.server.port", String.valueOf(config.getCmpPort()))));
            config.setCmpPath(props.getProperty("cmp.server.path", config.getCmpPath()));
            config.setCentralKeyKind(props.getProperty("central.key.kind", config.getCentralKeyKind()));
            config.setCentralKeyCurve(props.getProperty("central.key.curve", config.getCentralKeyCurve()));
            String centralKeySize = props.getProperty("central.key.size");
            if (centralKeySize != null) {
                config.setCentralKeySize(Integer.parseInt(centralKeySize));
            }
            
            LOG.info("Configuration loaded from {}", configPath);
            
        } catch (IOException e) {
            LOG.warn("No configuration file found at {}, using defaults", configPath);
        }
        
        // Override with command line arguments if provided
        if (args.length > 0) {
            config.setRestBaseUrl(args[0]);
        }
        if (args.length > 1) {
            config.setCaName(args[1]);
        }
        if (args.length > 2) {
            config.setTplName(args[2]);
        }
        
        return config;
    }
}
