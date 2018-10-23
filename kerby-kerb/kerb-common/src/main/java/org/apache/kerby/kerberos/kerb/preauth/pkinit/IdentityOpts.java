/**
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License.
 *
 */
package org.apache.kerby.kerberos.kerb.preauth.pkinit;

import java.util.ArrayList;
import java.util.List;

/*
 * Ref. MIT Krb5 _pkinit_identity_opts MIT krb5 project.
 */
public class IdentityOpts {

    private String identity;
    private List<String> altIdentities = new ArrayList<>(1);
    private List<String> anchors = new ArrayList<>(4);
    private List<String> intermediates = new ArrayList<>(2);
    private List<String> crls = new ArrayList<>(2);
    private String ocsp;
    private IdentityType idType;
    private String certFile;
    private String keyFile;

    // PKCS11
    private String p11ModuleName;
    private int slotid;
    private String tokenLabel;
    private String certId;
    private String certLabel;

    public String getIdentity() {
        return identity;
    }
    public void setIdentity(String identity) {
        this.identity = identity;
    }
    public List<String> getAltIdentities() {
        return altIdentities;
    }
    public void setAltIdentities(List<String> altIdentities) {
        this.altIdentities = altIdentities;
    }
    public List<String> getAnchors() {
        return anchors;
    }
    public void setAnchors(List<String> anchors) {
        this.anchors = anchors;
    }
    public List<String> getIntermediates() {
        return intermediates;
    }
    public void setIntermediates(List<String> intermediates) {
        this.intermediates = intermediates;
    }
    public List<String> getCrls() {
        return crls;
    }
    public void setCrls(List<String> crls) {
        this.crls = crls;
    }
    public String getOcsp() {
        return ocsp;
    }
    public void setOcsp(String ocsp) {
        this.ocsp = ocsp;
    }
    public IdentityType getIdType() {
        return idType;
    }
    public void setIdType(IdentityType idType) {
        this.idType = idType;
    }
    public String getCertFile() {
        return certFile;
    }
    public void setCertFile(String certFile) {
        this.certFile = certFile;
    }
    public String getKeyFile() {
        return keyFile;
    }
    public void setKeyFile(String keyFile) {
        this.keyFile = keyFile;
    }
    public String getP11ModuleName() {
        return p11ModuleName;
    }
    public void setP11ModuleName(String p11ModuleName) {
        this.p11ModuleName = p11ModuleName;
    }
    public int getSlotid() {
        return slotid;
    }
    public void setSlotid(int slotid) {
        this.slotid = slotid;
    }
    public String getTokenLabel() {
        return tokenLabel;
    }
    public void setTokenLabel(String tokenLabel) {
        this.tokenLabel = tokenLabel;
    }
    public String getCertId() {
        return certId;
    }
    public void setCertId(String certId) {
        this.certId = certId;
    }
    public String getCertLabel() {
        return certLabel;
    }
    public void setCertLabel(String certLabel) {
        this.certLabel = certLabel;
    }
}
