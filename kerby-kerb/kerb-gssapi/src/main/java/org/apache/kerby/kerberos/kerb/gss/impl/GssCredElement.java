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

import org.apache.kerby.kerberos.kerb.gss.KerbyGssProvider;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import sun.security.jgss.GSSCaller;
import sun.security.jgss.spi.GSSCredentialSpi;
import sun.security.jgss.spi.GSSNameSpi;

import java.security.Provider;

public abstract class GssCredElement implements GSSCredentialSpi {

    static final Oid KRB5_OID = createOid("1.2.840.113554.1.2.2");

    protected GSSCaller caller;
    protected GssNameElement name;
    protected int initLifeTime;
    protected int accLifeTime;

    GssCredElement(GSSCaller caller, GssNameElement name) {
        this.caller = caller;
        this.name = name;
    }

    public Provider getProvider() {
        return new KerbyGssProvider();
    }

    public void dispose() throws GSSException {
    }

    public GSSNameSpi getName() throws GSSException {
        return name;
    }

    public int getInitLifetime() throws GSSException {
        return initLifeTime;
    }

    public int getAcceptLifetime() throws GSSException {
        return accLifeTime;
    }

    public Oid getMechanism() {
        return KRB5_OID;
    }

    public GSSCredentialSpi impersonate(GSSNameSpi name) throws GSSException {
        throw new GSSException(GSSException.FAILURE, -1, "Unsupported feature");  // TODO:
    }

    private static Oid createOid(String oidStr) {
        Oid retVal;
        try {
            retVal = new Oid(oidStr);
        } catch (GSSException e) {
            retVal = null; // get rid of blank catch block warning
        }
        return retVal;
    }
}
