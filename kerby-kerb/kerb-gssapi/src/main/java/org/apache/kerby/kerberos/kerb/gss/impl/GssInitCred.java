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

import org.apache.kerby.kerberos.kerb.type.base.KrbToken;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;

import sun.security.jgss.GSSCaller;

import java.util.Set;

import javax.security.auth.kerberos.KerberosTicket;

public final class GssInitCred extends GssCredElement {

    private KerberosTicket ticket;
    private KrbToken krbToken;

    private GssInitCred(GSSCaller caller, GssNameElement name,
                        KerberosTicket ticket, KrbToken krbToken, int lifeTime) {
        super(caller, name);
        this.ticket = ticket;
        this.initLifeTime = lifeTime;
        this.krbToken = krbToken;
    }

    public static GssInitCred getInstance(GSSCaller caller, GssNameElement name, int lifeTime) throws GSSException {
        Set<KrbToken> krbTokens = CredUtils.getContextCredentials(KrbToken.class);
        KrbToken krbToken = krbTokens != null && !krbTokens.isEmpty() ? krbTokens.iterator().next() : null;

        if (name == null) {
            KerberosTicket ticket = CredUtils.getKerberosTicketFromContext(caller, null, null);
            GssNameElement clientName = GssNameElement.getInstance(ticket.getClient().getName(), GSSName.NT_USER_NAME);
            return new GssInitCred(caller, clientName, ticket, krbToken, lifeTime);
        }

        KerberosTicket ticket = CredUtils.getKerberosTicketFromContext(caller, name.getPrincipalName().getName(), null);
        return new GssInitCred(caller, name, ticket, krbToken, lifeTime);
    }

    public boolean isInitiatorCredential() throws GSSException {
        return true;
    }

    public boolean isAcceptorCredential() throws GSSException {
        return false;
    }

    public KerberosTicket getKerberosTicket() {
        return ticket;
    }

    public KrbToken getKrbToken() {
        return krbToken;
    }
}
