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

import javax.security.auth.kerberos.KerberosKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.security.auth.kerberos.KeyTab;

public final class GssAcceptCred extends GssCredElement {

    private final KeyTab keyTab;

    public static GssAcceptCred getInstance(final GSSCaller caller,
                                            GssNameElement name, int lifeTime) throws GSSException {

        KerberosPrincipal princ = new KerberosPrincipal(name.getPrincipalName().getName(),
                name.getPrincipalName().getNameType().getValue());
        KeyTab keyTab = CredUtils.getKeyTabFromContext(princ);

        if (keyTab == null) {
            throw new GSSException(GSSException.NO_CRED, -1,
                    "Failed to find any Kerberos credential for " + name.getPrincipalName().getName());
        }

        return new GssAcceptCred(caller, name, keyTab, lifeTime);
    }

    private GssAcceptCred(GSSCaller caller, GssNameElement name, KeyTab keyTab, int lifeTime) {
        super(caller, name);
        this.keyTab = keyTab;
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

    public KerberosKey[] getKeys() {
        KerberosPrincipal princ = new KerberosPrincipal(name.getPrincipalName().getName(),
                name.getPrincipalName().getNameType().getValue());
        return keyTab.getKeys(princ);
    }
}
