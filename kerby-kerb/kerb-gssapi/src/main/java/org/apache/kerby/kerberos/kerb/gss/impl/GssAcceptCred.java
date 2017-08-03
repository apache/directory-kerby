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
import org.ietf.jgss.GSSName;

import sun.security.jgss.GSSCaller;

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;
import java.util.Set;

public final class GssAcceptCred extends GssCredElement {

    private final KeyTab keyTab;
    private final Set<KerberosKey> kerberosKeySet;

    public static GssAcceptCred getInstance(final GSSCaller caller,
                                            GssNameElement name, int lifeTime) throws GSSException {

        // Try to get a keytab first
        KeyTab keyTab = getKeyTab(name);
        Set<KerberosKey> kerberosKeySet = null;
        if (keyTab == null) {
            // Otherwise try to get a kerberos key
            if (name == null) {
                kerberosKeySet = CredUtils.getKerberosKeysFromContext(caller, null, null);
            } else {
                kerberosKeySet = CredUtils.getKerberosKeysFromContext(caller, name.getPrincipalName().getName(), null);
            }
        }

        if (keyTab == null && kerberosKeySet == null) {
            String error = "Failed to find any Kerberos credential";
            if (name != null) {
                error +=  " for " + name.getPrincipalName().getName();
            }
            throw new GSSException(GSSException.NO_CRED, -1, error);
        }

        if (name == null) {
            if (keyTab != null) {
                name = GssNameElement.getInstance(keyTab.getPrincipal().getName(),
                    GSSName.NT_HOSTBASED_SERVICE);
            } else if (kerberosKeySet != null) {
                name = GssNameElement.getInstance(
                    kerberosKeySet.iterator().next().getPrincipal().getName(),
                    GSSName.NT_HOSTBASED_SERVICE);
            }
        }

        return new GssAcceptCred(caller, name, keyTab, lifeTime, kerberosKeySet);
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

    private GssAcceptCred(GSSCaller caller, GssNameElement name, KeyTab keyTab,
                          int lifeTime, Set<KerberosKey> kerberosKeySet) {
        super(caller, name);
        this.keyTab = keyTab;
        this.accLifeTime = lifeTime;
        this.kerberosKeySet = kerberosKeySet;
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

    public KerberosKey[] getKeys() {
        KerberosPrincipal princ = new KerberosPrincipal(name.getPrincipalName().getName(),
            name.getPrincipalName().getNameType().getValue());
        if (keyTab != null) {
            return keyTab.getKeys(princ);
        }

        return null;
    }

    public KerberosKey[] getKerberosKeys() {
        if (kerberosKeySet != null) {
            return kerberosKeySet.toArray(new KerberosKey[kerberosKeySet.size()]);
        }
        return null;
    }

}
