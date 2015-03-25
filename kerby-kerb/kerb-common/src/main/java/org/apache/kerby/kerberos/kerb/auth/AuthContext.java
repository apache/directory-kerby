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
package org.apache.kerby.kerberos.kerb.auth;

import org.apache.kerby.kerberos.kerb.spec.ap.Authenticator;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.spec.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.spec.base.HostAddress;
import org.apache.kerby.kerberos.kerb.spec.base.KrbFlags;

import java.util.List;

/**
 * Auth context shared by KDC and client for relevant information during auth.
 */
public class AuthContext {
    private KrbFlags flags;
    private HostAddress remoteAddress;
    private int remotePort;
    private HostAddress localAddress;
    private int localPort;
    private EncryptionKey key;
    private EncryptionKey sendSubkey;
    private EncryptionKey recvSubkey;
    private int remoteSeqNum;
    private int localSeqNum;
    private List<EncryptionType> permittedEncTypes;
    private EncryptionType negotiatedEncType;
    private Authenticator authenticator;

    public KrbFlags getFlags() {
        return flags;
    }

    public void setFlags(KrbFlags flags) {
        this.flags = flags;
    }

    public HostAddress getRemoteAddress() {
        return remoteAddress;
    }

    public void setRemoteAddress(HostAddress remoteAddress) {
        this.remoteAddress = remoteAddress;
    }

    public int getRemotePort() {
        return remotePort;
    }

    public void setRemotePort(int remotePort) {
        this.remotePort = remotePort;
    }

    public HostAddress getLocalAddress() {
        return localAddress;
    }

    public void setLocalAddress(HostAddress localAddress) {
        this.localAddress = localAddress;
    }

    public int getLocalPort() {
        return localPort;
    }

    public void setLocalPort(int localPort) {
        this.localPort = localPort;
    }

    public EncryptionKey getKey() {
        return key;
    }

    public void setKey(EncryptionKey key) {
        this.key = key;
    }

    public EncryptionKey getSendSubkey() {
        return sendSubkey;
    }

    public void setSendSubkey(EncryptionKey sendSubkey) {
        this.sendSubkey = sendSubkey;
    }

    public EncryptionKey getRecvSubkey() {
        return recvSubkey;
    }

    public void setRecvSubkey(EncryptionKey recvSubkey) {
        this.recvSubkey = recvSubkey;
    }

    public int getRemoteSeqNum() {
        return remoteSeqNum;
    }

    public void setRemoteSeqNum(int remoteSeqNum) {
        this.remoteSeqNum = remoteSeqNum;
    }

    public int getLocalSeqNum() {
        return localSeqNum;
    }

    public void setLocalSeqNum(int localSeqNum) {
        this.localSeqNum = localSeqNum;
    }

    public List<EncryptionType> getPermittedEncTypes() {
        return permittedEncTypes;
    }

    public void setPermittedEncTypes(List<EncryptionType> permittedEncTypes) {
        this.permittedEncTypes = permittedEncTypes;
    }

    public EncryptionType getNegotiatedEncType() {
        return negotiatedEncType;
    }

    public void setNegotiatedEncType(EncryptionType negotiatedEncType) {
        this.negotiatedEncType = negotiatedEncType;
    }

    public Authenticator getAuthenticator() {
        return authenticator;
    }

    public void setAuthenticator(Authenticator authenticator) {
        this.authenticator = authenticator;
    }
}
