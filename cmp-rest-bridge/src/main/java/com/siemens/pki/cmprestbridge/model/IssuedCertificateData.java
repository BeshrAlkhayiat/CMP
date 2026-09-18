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
