package com.siemens.pki.cmprestbridge.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Meta information about a certificate.
 * Maps to CertificateMeta schema.
 */
public class CertificateMeta {
    
    @JsonProperty("serial")
    private String serial;
    
    @JsonProperty("subject")
    private String subject;
    
    @JsonProperty("issuer")
    private String issuer;
    
    @JsonProperty("notBefore")
    private String notBefore;
    
    @JsonProperty("notAfter")
    private String notAfter;
    
    @JsonProperty("fingerprint")
    private String fingerprint;

    public CertificateMeta() {}

    public String getSerial() {
        return serial;
    }

    public void setSerial(String serial) {
        this.serial = serial;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getNotBefore() {
        return notBefore;
    }

    public void setNotBefore(String notBefore) {
        this.notBefore = notBefore;
    }

    public String getNotAfter() {
        return notAfter;
    }

    public void setNotAfter(String notAfter) {
        this.notAfter = notAfter;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }
}
