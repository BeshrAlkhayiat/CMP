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
 * Data for requesting a certificate with a CSR (PKCS#10).
 * Maps to CertificateRequestSign schema from the REST API.
 */
public class CertificateRequestSign {
    
    @JsonProperty("csr")
    private String csr;
    
    @JsonProperty("proto")
    private String proto = "CMP";
    
    @JsonProperty("session")
    private String session;
    
    @JsonProperty("commonName")
    private String commonName;
    
    @JsonProperty("mail")
    private String mail;
    
    @JsonProperty("dnSuffix")
    private String dnSuffix;
    
    @JsonProperty("SAN")
    private SAN san;
    
    @JsonProperty("validityStart")
    private String validityStart;
    
    @JsonProperty("validity")
    private String validity;
    
    @JsonProperty("returnIssuer")
    private boolean returnIssuer = true;
    
    @JsonProperty("returnChain")
    private boolean returnChain = true;
    
    @JsonProperty("returnRoot")
    private boolean returnRoot = false;
    
    @JsonProperty("format")
    private String format = "DER";
    
    @JsonProperty("notify")
    private String notify;
    
    @JsonProperty("renew")
    private String renew;
    
    @JsonProperty("input")
    private String input;

    public CertificateRequestSign() {}

    public String getCsr() {
        return csr;
    }

    public void setCsr(String csr) {
        this.csr = csr;
    }

    public String getProto() {
        return proto;
    }

    public void setProto(String proto) {
        this.proto = proto;
    }

    public String getSession() {
        return session;
    }

    public void setSession(String session) {
        this.session = session;
    }

    public String getCommonName() {
        return commonName;
    }

    public void setCommonName(String commonName) {
        this.commonName = commonName;
    }

    public String getMail() {
        return mail;
    }

    public void setMail(String mail) {
        this.mail = mail;
    }

    public String getDnSuffix() {
        return dnSuffix;
    }

    public void setDnSuffix(String dnSuffix) {
        this.dnSuffix = dnSuffix;
    }

    public SAN getSan() {
        return san;
    }

    public void setSan(SAN san) {
        this.san = san;
    }

    public String getValidityStart() {
        return validityStart;
    }

    public void setValidityStart(String validityStart) {
        this.validityStart = validityStart;
    }

    public String getValidity() {
        return validity;
    }

    public void setValidity(String validity) {
        this.validity = validity;
    }

    public boolean isReturnIssuer() {
        return returnIssuer;
    }

    public void setReturnIssuer(boolean returnIssuer) {
        this.returnIssuer = returnIssuer;
    }

    public boolean isReturnChain() {
        return returnChain;
    }

    public void setReturnChain(boolean returnChain) {
        this.returnChain = returnChain;
    }

    public boolean isReturnRoot() {
        return returnRoot;
    }

    public void setReturnRoot(boolean returnRoot) {
        this.returnRoot = returnRoot;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getNotify() {
        return notify;
    }

    public void setNotify(String notify) {
        this.notify = notify;
    }

    public String getRenew() {
        return renew;
    }

    public void setRenew(String renew) {
        this.renew = renew;
    }

    public String getInput() {
        return input;
    }

    public void setInput(String input) {
        this.input = input;
    }
}
