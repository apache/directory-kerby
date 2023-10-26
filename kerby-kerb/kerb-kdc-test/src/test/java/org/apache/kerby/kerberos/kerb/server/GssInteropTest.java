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
package org.apache.kerby.kerberos.kerb.server;

import java.security.Principal;
import java.security.PrivilegedExceptionAction;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosTicket;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * This is an interop test using the Java GSS APIs against the Kerby KDC
 */
public class GssInteropTest extends LoginTestBase {

    @Test
    public void testGss() throws Exception {
        Subject clientSubject = loginClientUsingTicketCache();
        Set<Principal> clientPrincipals = clientSubject.getPrincipals();
        Assertions.assertFalse(clientPrincipals.isEmpty());

        // Get the TGT
        Set<KerberosTicket> privateCredentials =
                clientSubject.getPrivateCredentials(KerberosTicket.class);
        Assertions.assertFalse(privateCredentials.isEmpty());
        KerberosTicket tgt = privateCredentials.iterator().next();
        Assertions.assertNotNull(tgt);

        // Get the service ticket
        KerberosClientExceptionAction action =
                new KerberosClientExceptionAction(clientPrincipals.iterator().next(),
                        getServerPrincipal());

        byte[] kerberosToken = (byte[]) Subject.doAs(clientSubject, action);
        Assertions.assertNotNull(kerberosToken);

        validateServiceTicket(kerberosToken);
    }

    private void validateServiceTicket(byte[] ticket) throws Exception {
        Subject serviceSubject = loginServiceUsingKeytab();
        Set<Principal> servicePrincipals = serviceSubject.getPrincipals();
        Assertions.assertFalse(servicePrincipals.isEmpty());

        // Handle the service ticket
        KerberosServiceExceptionAction serviceAction =
                new KerberosServiceExceptionAction(ticket, getServerPrincipal());

        Subject.doAs(serviceSubject, serviceAction);
    }

    private static class KerberosServiceExceptionAction
            implements PrivilegedExceptionAction<byte[]> {

        private static final String JGSS_KERBEROS_TICKET_OID = "1.2.840.113554.1.2.2";

        private byte[] ticket;
        private String serviceName;

        KerberosServiceExceptionAction(byte[] ticket, String serviceName) {
            this.ticket = ticket;
            this.serviceName = serviceName;
        }

        public byte[] run() throws GSSException {
            GSSManager gssManager = GSSManager.getInstance();
            GSSContext secContext;
            GSSName gssService = gssManager.createName(serviceName,
                    GSSName.NT_USER_NAME);

            Oid oid = new Oid(JGSS_KERBEROS_TICKET_OID);
            GSSCredential credentials = gssManager.createCredential(
                            gssService, GSSCredential.DEFAULT_LIFETIME,
                            oid, GSSCredential.ACCEPT_ONLY);
            secContext = gssManager.createContext(credentials);

            try {
                return secContext.acceptSecContext(ticket, 0, ticket.length);
            } finally {
                if (null != secContext) {
                    secContext.dispose();
                }
            }
        }

    }
}
