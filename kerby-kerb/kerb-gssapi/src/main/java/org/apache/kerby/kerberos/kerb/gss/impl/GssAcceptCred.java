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
package org.apache.kerby.kerberos.kerb.gss.impl;


import org.apache.kerby.kerberos.kerb.type.base.EncryptionKey;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

import sun.security.jgss.GSSCaller;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KerberosTicket;
import javax.security.auth.kerberos.KeyTab;

public final class GssAcceptCred extends GssCredElement {

    private final KeyTab keyTab;
    private final KerberosTicket ticket;

    public static GssAcceptCred getInstance(final GSSCaller caller,
                                            GssNameElement name, int lifeTime) throws GSSException {

        // Try to get a keytab first
        KeyTab keyTab = getKeyTab(name);
        KerberosTicket ticket = null;
        if (keyTab == null) {
            // Otherwise try to get a kerberos ticket
            if (name == null) {
                ticket = CredUtils.getKerberosTicketFromContext(caller, null, null);
            } else {
                ticket = CredUtils.getKerberosTicketFromContext(caller, name.getPrincipalName().getName(), null);
            }
        }

        if (keyTab == null && ticket == null) {
            String error = "Failed to find any Kerberos credential";
            if (name != null) {
                error +=  " for " + name.getPrincipalName().getName();
            }
            throw new GSSException(GSSException.NO_CRED, -1, error);
        }

        if (name == null) {
            if (keyTab != null) {
                name = GssNameElement.getInstance(keyTab.getPrincipal().getName(), GSSName.NT_HOSTBASED_SERVICE);
            } else {
                name = GssNameElement.getInstance(ticket.getClient().getName(), GSSName.NT_HOSTBASED_SERVICE);
            }
        }

        return new GssAcceptCred(caller, name, keyTab, ticket, lifeTime);
    }

    private static KeyTab getKeyTab(GssNameElement name) throws GSSException {
        if (name == null) {
            return CredUtils.getKeyTabFromContext(null);
        } else {
            KerberosPrincipal princ = new KerberosPrincipal(name.getPrincipalName().getName(),
                                                            name.getPrincipalName().getNameType().getValue());
            return CredUtils.getKeyTabFromContext(princ);
        }
    }

    private GssAcceptCred(GSSCaller caller, GssNameElement name, KeyTab keyTab, KerberosTicket ticket, int lifeTime) {
        super(caller, name);
        this.keyTab = keyTab;
        this.ticket = ticket;
        this.accLifeTime = lifeTime;
    }

    public boolean isInitiatorCredential() throws GSSException {
        return false;
    }

    public boolean isAcceptorCredential() throws GSSException {
        return true;
    }

    public KeyTab getKeyTab() {
        return this.keyTab;
    }

    public KerberosTicket getKerberosTicket() {
        return ticket;
    }

    public KerberosKey[] getKeys() {
        KerberosPrincipal princ = new KerberosPrincipal(name.getPrincipalName().getName(),
                name.getPrincipalName().getNameType().getValue());
        if (keyTab != null) {
            return keyTab.getKeys(princ);
        }

        return null;
    }

    public EncryptionKey getKeyFromTicket() {
        if (ticket != null) {
            return new EncryptionKey(ticket.getSessionKeyType(), ticket.getSessionKey().getEncoded());
        }
        return null;
    }
}
