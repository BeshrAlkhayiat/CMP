package com.siemens.pki.cmprestbridge.config;

import com.siemens.pki.cmpracomponent.configuration.InventoryInterface;
import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * Configuration for the CMP-to-REST Bridge.
 * 
 * This class holds all configuration parameters needed to set up the bridge
 * between CMP end entities and a REST-based PKI backend.
 */
public class BridgeConfiguration {
    
    // REST API settings
    private String restApiBaseUrl = "https://pki.example.com/api";
    private String caName = "defaultCA";
    private String restApiToken;
    
    // Downstream CMP interface settings (towards end entities)
    private String downstreamProtectionType = "signature"; // signature, mac, or none
    private String downstreamKeystorePath;
    private String downstreamKeystorePassword;
    private String downstreamKeyAlias;
    private String downstreamKeyPassword;
    private byte[] downstreamSharedSecret;
    private Collection<X509Certificate> downstreamTrustedCerts;
    private int downstreamTimeoutSeconds = 60;
    
    // Enrollment verification
    private Collection<X509Certificate> enrollmentTrustedCerts;
    
    // General settings
    private int messageTimeDeviationSeconds = 300; // 5 minutes
    private boolean cacheExtraCerts = false;
    private int pollingIntervalSeconds = 30;
    private String defaultValidity = "1y";
    
    // Optional custom handlers
    private InventoryInterface inventoryHandler;

    public BridgeConfiguration() {}

    // Getters and Setters
    
    public String getRestApiBaseUrl() {
        return restApiBaseUrl;
    }

    public void setRestApiBaseUrl(String restApiBaseUrl) {
        this.restApiBaseUrl = restApiBaseUrl;
    }

    public String getCaName() {
        return caName;
    }

    public void setCaName(String caName) {
        this.caName = caName;
    }

    public String getRestApiToken() {
        return restApiToken;
    }

    public void setRestApiToken(String restApiToken) {
        this.restApiToken = restApiToken;
    }

    public String getDownstreamProtectionType() {
        return downstreamProtectionType;
    }

    public void setDownstreamProtectionType(String downstreamProtectionType) {
        this.downstreamProtectionType = downstreamProtectionType;
    }

    public String getDownstreamKeystorePath() {
        return downstreamKeystorePath;
    }

    public void setDownstreamKeystorePath(String downstreamKeystorePath) {
        this.downstreamKeystorePath = downstreamKeystorePath;
    }

    public String getDownstreamKeystorePassword() {
        return downstreamKeystorePassword;
    }

    public void setDownstreamKeystorePassword(String downstreamKeystorePassword) {
        this.downstreamKeystorePassword = downstreamKeystorePassword;
    }

    public String getDownstreamKeyAlias() {
        return downstreamKeyAlias;
    }

    public void setDownstreamKeyAlias(String downstreamKeyAlias) {
        this.downstreamKeyAlias = downstreamKeyAlias;
    }

    public String getDownstreamKeyPassword() {
        return downstreamKeyPassword;
    }

    public void setDownstreamKeyPassword(String downstreamKeyPassword) {
        this.downstreamKeyPassword = downstreamKeyPassword;
    }

    public byte[] getDownstreamSharedSecret() {
        return downstreamSharedSecret;
    }

    public void setDownstreamSharedSecret(byte[] downstreamSharedSecret) {
        this.downstreamSharedSecret = downstreamSharedSecret;
    }

    public Collection<X509Certificate> getDownstreamTrustedCerts() {
        return downstreamTrustedCerts;
    }

    public void setDownstreamTrustedCerts(Collection<X509Certificate> downstreamTrustedCerts) {
        this.downstreamTrustedCerts = downstreamTrustedCerts;
    }

    public int getDownstreamTimeoutSeconds() {
        return downstreamTimeoutSeconds;
    }

    public void setDownstreamTimeoutSeconds(int downstreamTimeoutSeconds) {
        this.downstreamTimeoutSeconds = downstreamTimeoutSeconds;
    }

    public Collection<X509Certificate> getEnrollmentTrustedCerts() {
        return enrollmentTrustedCerts;
    }

    public void setEnrollmentTrustedCerts(Collection<X509Certificate> enrollmentTrustedCerts) {
        this.enrollmentTrustedCerts = enrollmentTrustedCerts;
    }

    public int getMessageTimeDeviationSeconds() {
        return messageTimeDeviationSeconds;
    }

    public void setMessageTimeDeviationSeconds(int messageTimeDeviationSeconds) {
        this.messageTimeDeviationSeconds = messageTimeDeviationSeconds;
    }

    public boolean isCacheExtraCerts() {
        return cacheExtraCerts;
    }

    public void setCacheExtraCerts(boolean cacheExtraCerts) {
        this.cacheExtraCerts = cacheExtraCerts;
    }

    public int getPollingIntervalSeconds() {
        return pollingIntervalSeconds;
    }

    public void setPollingIntervalSeconds(int pollingIntervalSeconds) {
        this.pollingIntervalSeconds = pollingIntervalSeconds;
    }

    public String getDefaultValidity() {
        return defaultValidity;
    }

    public void setDefaultValidity(String defaultValidity) {
        this.defaultValidity = defaultValidity;
    }

    public InventoryInterface getInventoryHandler() {
        return inventoryHandler;
    }

    public void setInventoryHandler(InventoryInterface inventoryHandler) {
        this.inventoryHandler = inventoryHandler;
    }

    /**
     * Builder pattern for fluent configuration.
     */
    public static class Builder {
        private final BridgeConfiguration config = new BridgeConfiguration();

        public Builder restApiBaseUrl(String url) {
            config.setRestApiBaseUrl(url);
            return this;
        }

        public Builder caName(String name) {
            config.setCaName(name);
            return this;
        }

        public Builder restApiToken(String token) {
            config.setRestApiToken(token);
            return this;
        }

        public Builder downstreamProtection(String type) {
            config.setDownstreamProtectionType(type);
            return this;
        }

        public Builder downstreamKeystore(String path, String password, String alias, String keyPassword) {
            config.setDownstreamKeystorePath(path);
            config.setDownstreamKeystorePassword(password);
            config.setDownstreamKeyAlias(alias);
            config.setDownstreamKeyPassword(keyPassword);
            return this;
        }

        public Builder downstreamSharedSecret(byte[] secret) {
            config.setDownstreamSharedSecret(secret);
            return this;
        }

        public Builder downstreamTrustedCerts(Collection<X509Certificate> certs) {
            config.setDownstreamTrustedCerts(certs);
            return this;
        }

        public Builder enrollmentTrustedCerts(Collection<X509Certificate> certs) {
            config.setEnrollmentTrustedCerts(certs);
            return this;
        }

        public Builder messageTimeDeviationSeconds(int seconds) {
            config.setMessageTimeDeviationSeconds(seconds);
            return this;
        }

        public Builder pollingIntervalSeconds(int seconds) {
            config.setPollingIntervalSeconds(seconds);
            return this;
        }

        public Builder defaultValidity(String validity) {
            config.setDefaultValidity(validity);
            return this;
        }

        public Builder inventoryHandler(InventoryInterface handler) {
            config.setInventoryHandler(handler);
            return this;
        }

        public BridgeConfiguration build() {
            return config;
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
