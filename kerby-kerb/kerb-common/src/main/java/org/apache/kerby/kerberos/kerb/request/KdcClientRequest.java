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
package org.apache.kerby.kerberos.kerb.request;

import java.net.InetAddress;

import org.apache.kerby.kerberos.kerb.type.base.AuthToken;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.apache.kerby.kerberos.kerb.type.base.EncryptionType;
import org.apache.kerby.kerberos.kerb.type.base.KrbMessageType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.ticket.Ticket;

/**
 * This class holds details of the client request which is passed through to the IdentityService
 * to create the AuthorizationData
 */
public class KdcClientRequest {

    private KrbMessageType msgType;
    private Ticket tgt;
    private PrincipalName tgsName;
    private EncryptionType tgsKeyType;
    private EncryptionKey tgsKey;
    private EncryptionKey tgsSessionKey;
    private EncryptionKey tgsServerKey;
    
    private boolean isPreAuthenticated;
    private InetAddress clientAddress;
    private EncryptionType encryptionType;
    private EncryptionKey clientKey;
    private PrincipalName clientPrincipal;
    private KrbIdentity clientEntry;
    private PrincipalName serverPrincipal;
    private KrbIdentity serverEntry;
    private String kdcRealm;
    private AuthToken token;
    private boolean isToken;
    private boolean isPkinit;
    private boolean isAnonymous;

    public KrbMessageType getMsgType() {
        return msgType;
    }

    public void setMsgType(KrbMessageType msgType) {
        this.msgType = msgType;
    }

    public Ticket getTgt() {
        return tgt;
    }

    public void setTgt(Ticket tgt) {
        this.tgt = tgt;
    }

    public PrincipalName getTgsName() {
        return tgsName;
    }

    public void setTgsName(PrincipalName tgsName) {
        this.tgsName = tgsName;
    }

    public EncryptionType getTgsKeyType() {
        return tgsKeyType;
    }

    public void setTgsKeyType(EncryptionType tgsKeyType) {
        this.tgsKeyType = tgsKeyType;
    }

    public EncryptionKey getTgsKey() {
        return tgsKey;
    }

    public void setTgsKey(EncryptionKey tgsKey) {
        this.tgsKey = tgsKey;
    }

    public String getKdcRealm() {
        return kdcRealm;
    }

    public void setKdcRealm(String kdcRealm) {
        this.kdcRealm = kdcRealm;
    }

    public EncryptionKey getTgsSessionKey() {
        return tgsSessionKey;
    }

    public void setTgsSessionKey(EncryptionKey tgsSessionKey) {
        this.tgsSessionKey = tgsSessionKey;
    }

    public EncryptionKey getTgsServerKey() {
        return tgsServerKey;
    }

    public void setTgsServerKey(EncryptionKey tgsServerKey) {
        this.tgsServerKey = tgsServerKey;
    }

    public KrbIdentity getClientEntry() {
        return clientEntry;
    }

    public void setClientEntry(KrbIdentity clientEntry) {
        this.clientEntry = clientEntry;
    }

    public KrbIdentity getServerEntry() {
        return serverEntry;
    }

    public void setServerEntry(KrbIdentity serverEntry) {
        this.serverEntry = serverEntry;
    }

    public boolean isPreAuthenticated() {
        return isPreAuthenticated;
    }

    public void setPreAuthenticated(boolean isPreAuthenticated) {
        this.isPreAuthenticated = isPreAuthenticated;
    }

    public InetAddress getClientAddress() {
        return clientAddress;
    }

    public void setClientAddress(InetAddress clientAddress) {
        this.clientAddress = clientAddress;
    }

    public EncryptionType getEncryptionType() {
        return encryptionType;
    }

    public void setEncryptionType(EncryptionType encryptionType) {
        this.encryptionType = encryptionType;
    }

    public EncryptionKey getClientKey() {
        return clientKey;
    }

    public void setClientKey(EncryptionKey clientKey) {
        this.clientKey = clientKey;
    }

    public PrincipalName getClientPrincipal() {
        return clientPrincipal;
    }

    public void setClientPrincipal(PrincipalName clientPrincipal) {
        this.clientPrincipal = clientPrincipal;
    }

    public PrincipalName getServerPrincipal() {
        return serverPrincipal;
    }

    public void setServerPrincipal(PrincipalName serverPrincipal) {
        this.serverPrincipal = serverPrincipal;
    }

    public AuthToken getToken() {
        return token;
    }

    public void setToken(AuthToken token) {
        this.token = token;
    }

    public boolean isToken() {
        return isToken;
    }

    public void setIsToken(boolean isToken) {
        this.isToken = isToken;
    }

    public boolean isPkinit() {
        return isPkinit;
    }

    public void setPkinit(boolean isPkinit) {
        this.isPkinit = isPkinit;
    }

    public boolean isAnonymous() {
        return isAnonymous;
    }

    public void setAnonymous(boolean isAnonymous) {
        this.isAnonymous = isAnonymous;
    }

}
