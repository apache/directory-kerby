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

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;

/**
 * This class represents a PrivilegedExceptionAction implementation to
 * a service ticket from a Kerberos Key Distribution Center.
 */
public class KerberosClientExceptionAction implements PrivilegedExceptionAction<byte[]> {

    private static final String JGSS_KERBEROS_TICKET_OID = "1.2.840.113554.1.2.2";

    private Principal clientPrincipal;
    private String serviceName;

    public KerberosClientExceptionAction(Principal clientPrincipal, String serviceName) {
        this.clientPrincipal = clientPrincipal;
        this.serviceName = serviceName;
    }

    public byte[] run() throws GSSException {
        GSSManager gssManager = GSSManager.getInstance();

        GSSName gssService = gssManager.createName(serviceName,
                                                   GSSName.NT_USER_NAME);
        Oid oid = new Oid(JGSS_KERBEROS_TICKET_OID);
        GSSName gssClient = gssManager.createName(clientPrincipal.getName(),
                                                  GSSName.NT_USER_NAME);
        GSSCredential credentials =
            gssManager.createCredential(gssClient, GSSCredential.DEFAULT_LIFETIME, oid,
                                        GSSCredential.INITIATE_ONLY);

        GSSContext secContext =
            gssManager.createContext(gssService, oid, credentials, GSSContext.DEFAULT_LIFETIME);

        secContext.requestMutualAuth(false);
        secContext.requestCredDeleg(false);

        try {
            byte[] token = new byte[0];
            byte[] returnedToken = secContext.initSecContext(token,
                                                             0, token.length);
            return returnedToken;
        } finally {
            secContext.dispose();
        }
    }
}