package com.siemens.pki.cmprestbridge.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

/**
 * Response containing issued certificate data from the REST API.
 * Maps to IssuedCertificateData schema.
 */
public class IssuedCertificateData {
    
    @JsonProperty("info")
    private CertificateMeta info;
    
    @JsonProperty("uuid")
    private String uuid;
    
    @JsonProperty("key")
    private String key;
    
    @JsonProperty("cert")
    private String cert;
    
    @JsonProperty("issuer")
    private String issuer;
    
    @JsonProperty("chain")
    private List<String> chain;
    
    @JsonProperty("root")
    private String root;

    public IssuedCertificateData() {}

    public CertificateMeta getInfo() {
        return info;
    }

    public void setInfo(CertificateMeta info) {
        this.info = info;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getCert() {
        return cert;
    }

    public void setCert(String cert) {
        this.cert = cert;
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public List<String> getChain() {
        return chain;
    }

    public void setChain(List<String> chain) {
        this.chain = chain;
    }

    public String getRoot() {
        return root;
    }

    public void setRoot(String root) {
        this.root = root;
    }
}
