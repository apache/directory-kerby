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
package org.apache.kerby.kerberos.kerb.gssapi;

import org.apache.kerby.kerberos.kerb.gssapi.krb5.KerbyAcceptCred;
import org.apache.kerby.kerberos.kerb.gssapi.krb5.KerbyContext;
import org.apache.kerby.kerberos.kerb.gssapi.krb5.KerbyCredElement;
import org.apache.kerby.kerberos.kerb.gssapi.krb5.KerbyInitCred;
import org.apache.kerby.kerberos.kerb.gssapi.krb5.KerbyNameElement;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.spi.GSSContextSpi;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;
import sun.security.jgss.spi.MechanismFactory;

import java.security.Provider;

/**
 * Kerby Kerberos V5 plugin for JGSS
 */
public class KerbyMechFactory implements MechanismFactory {
    private static final Provider PROVIDER =
            new org.apache.kerby.kerberos.kerb.gssapi.Provider();

    private static final String KRB5_OID_STRING = "1.2.840.113554.1.2.2";
    private static final Oid KRB5_OID = createOid(KRB5_OID_STRING);

    private static Oid[] nameTypes =
            new Oid[] {
                    GSSName.NT_USER_NAME,
                    GSSName.NT_EXPORT_NAME,
                    GSSName.NT_HOSTBASED_SERVICE
            };

    private final GSSCaller caller;

    public Oid getMechanismOid() {
        return KRB5_OID;
    }

    public Provider getProvider() {
        return PROVIDER;
    }

    public Oid[] getNameTypes() throws GSSException {
        return nameTypes;
    }

    public KerbyMechFactory(GSSCaller caller) {
        this.caller = caller;
    }

    public GSSNameSpi getNameElement(String nameStr, Oid nameType)
            throws GSSException {
        return KerbyNameElement.getInstance(nameStr, nameType);
    }

    public GSSNameSpi getNameElement(byte[] name, Oid nameType)
            throws GSSException {
        return KerbyNameElement.getInstance(name.toString(), nameType);
    }

    // Used by initiator
    public GSSContextSpi getMechanismContext(GSSNameSpi peer,
                                             GSSCredentialSpi myInitiatorCred,
                                             int lifetime) throws GSSException {
        if (peer != null && !(peer instanceof KerbyNameElement)) {
            peer = KerbyNameElement.getInstance(peer.toString(), peer.getStringNameType());
        }
        if (myInitiatorCred == null) {
            myInitiatorCred = getCredentialElement(null, lifetime, 0, GSSCredential.INITIATE_ONLY);
        }
        return new KerbyContext(caller, (KerbyNameElement) peer, (KerbyInitCred) myInitiatorCred, lifetime);
    }

    public GSSContextSpi getMechanismContext(GSSCredentialSpi myAcceptorCred)
            throws GSSException {
        if (myAcceptorCred == null) {
            myAcceptorCred = getCredentialElement(null, 0,
                    GSSCredential.INDEFINITE_LIFETIME, GSSCredential.ACCEPT_ONLY);
        }
        return new KerbyContext(caller, (KerbyAcceptCred) myAcceptorCred);
    }

    // Reconstruct from previously exported context
    public GSSContextSpi getMechanismContext(byte[] exportedContext)
            throws GSSException {
       return new KerbyContext(caller, exportedContext);
    }

    public GSSCredentialSpi getCredentialElement(GSSNameSpi name,
                                                 int initLifetime,
                                                 int acceptLifetime,
                                                 int usage)
            throws GSSException {
        if (name != null && !(name instanceof KerbyNameElement)) {
            name = KerbyNameElement.getInstance(name.toString(), name.getStringNameType());
        }

        KerbyCredElement credElement;

        if (usage == GSSCredential.INITIATE_ONLY) {
            credElement = KerbyInitCred.getInstance(caller, (KerbyNameElement) name, initLifetime);
        } else if (usage == GSSCredential.ACCEPT_ONLY) {
            credElement = KerbyAcceptCred.getInstance(caller, (KerbyNameElement) name, acceptLifetime);
        } else if (usage == GSSCredential.INITIATE_AND_ACCEPT) {
            throw new GSSException(GSSException.FAILURE, -1, "Unsupported usage mode: INITIATE_AND_ACCEPT");
        } else {
            throw new GSSException(GSSException.FAILURE, -1, "Unknown usage mode: " + usage);
        }

        return credElement;
    }

    private static Oid createOid(String oidStr) {
        Oid retVal;
        try {
            retVal = new Oid(oidStr);
        } catch (GSSException e) {
            retVal = null;
        }
        return retVal;
    }

    public static Oid getOid() {
        return KRB5_OID;
    }
}
