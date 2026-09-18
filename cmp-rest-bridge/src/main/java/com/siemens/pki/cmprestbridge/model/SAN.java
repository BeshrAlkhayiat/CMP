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
 * Subject Alternative Names (SANs) for certificate requests.
 */
public class SAN {
    
    @JsonProperty("DNS")
    private List<String> dns;
    
    @JsonProperty("mail")
    private List<String> mail;
    
    @JsonProperty("IP")
    private List<String> ip;
    
    @JsonProperty("URI")
    private List<String> uri;
    
    @JsonProperty("dir")
    private List<String> dir;
    
    @JsonProperty("OID")
    private List<String> oid;
    
    @JsonProperty("GUID")
    private String guid;
    
    @JsonProperty("principalName")
    private String principalName;

    public SAN() {}

    public List<String> getDns() {
        return dns;
    }

    public void setDns(List<String> dns) {
        this.dns = dns;
    }

    public List<String> getMail() {
        return mail;
    }

    public void setMail(List<String> mail) {
        this.mail = mail;
    }

    public List<String> getIp() {
        return ip;
    }

    public void setIp(List<String> ip) {
        this.ip = ip;
    }

    public List<String> getUri() {
        return uri;
    }

    public void setUri(List<String> uri) {
        this.uri = uri;
    }

    public List<String> getDir() {
        return dir;
    }

    public void setDir(List<String> dir) {
        this.dir = dir;
    }

    public List<String> getOid() {
        return oid;
    }

    public void setOid(List<String> oid) {
        this.oid = oid;
    }

    public String getGuid() {
        return guid;
    }

    public void setGuid(String guid) {
        this.guid = guid;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }
}
