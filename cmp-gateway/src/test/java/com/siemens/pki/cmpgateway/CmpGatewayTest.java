/*
 *  Copyright (c) 2024 Siemens AG
 *  Licensed under the Apache License, Version 2.0
 */
package com.siemens.pki.cmpgateway;

import com.siemens.pki.cmpgateway.config.GatewayConfig;
import com.siemens.pki.cmpgateway.rest.RestClient;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Basic integration tests for CMP Gateway.
 */
public class CmpGatewayTest {
    
    @Test
    public void testConfigDefaults() {
        GatewayConfig config = new GatewayConfig();
        
        assertNotNull(config.getRestBaseUrl());
        assertNotNull(config.getCaName());
        assertNotNull(config.getTplName());
        assertEquals("certificate", config.getAuthType());
        assertEquals(30, config.getRetryAfterSeconds());
        assertEquals(300, config.getDownstreamTimeoutSeconds());
    }
    
    @Test
    public void testConfigSetters() {
        GatewayConfig config = new GatewayConfig();
        
        config.setRestBaseUrl("https://test.example.com/rest");
        config.setCaName("TEST_CA");
        config.setTplName("USER_CERT");
        config.setAuthType("basic");
        config.setUsername("testuser");
        config.setPassword("testpass");
        config.setRetryAfterSeconds(60);
        
        assertEquals("https://test.example.com/rest", config.getRestBaseUrl());
        assertEquals("TEST_CA", config.getCaName());
        assertEquals("USER_CERT", config.getTplName());
        assertEquals("basic", config.getAuthType());
        assertEquals("testuser", config.getUsername());
        assertEquals("testpass", config.getPassword());
        assertEquals(60, config.getRetryAfterSeconds());
    }
    
    @Test
    public void testSharedSecret() {
        GatewayConfig config = new GatewayConfig();
        
        byte[] secret = config.getSharedSecret();
        assertNotNull(secret);
        assertTrue(secret.length > 0);
        
        // Set custom secret
        config.setSharedSecret("custom-secret".getBytes());
        assertArrayEquals("custom-secret".getBytes(), config.getSharedSecret());
    }
}
