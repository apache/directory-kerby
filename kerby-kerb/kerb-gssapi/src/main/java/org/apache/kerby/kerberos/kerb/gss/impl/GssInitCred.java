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

import org.ietf.jgss.GSSException;
import sun.security.jgss.GSSCaller;

import javax.security.auth.kerberos.KerberosTicket;

public final class GssInitCred extends GssCredElement {

    public KerberosTicket ticket;

    private GssInitCred(GSSCaller caller, GssNameElement name, KerberosTicket ticket, int lifeTime) {
        super(caller, name);
        this.ticket = ticket;
        this.initLifeTime = lifeTime;
    }

    public static GssInitCred getInstance(GSSCaller caller, GssNameElement name, int lifeTime) throws GSSException {
        KerberosTicket ticket = CredUtils.getKerberosTicketFromContext(caller, name.getPrincipalName().getName(), null);
        return new GssInitCred(caller, name, ticket, lifeTime);
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
}
