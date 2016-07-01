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

import org.apache.kerby.kerberos.kerb.gss.GssMechFactory;
import org.apache.kerby.kerberos.kerb.gss.KerbyGssProvider;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import sun.security.jgss.spi.GSSNameSpi;
import java.io.UnsupportedEncodingException;
import java.security.Provider;

public class GssNameElement implements GSSNameSpi {

    private PrincipalName principalName;
    private Oid nameType = null;

    GssNameElement(PrincipalName principalName,
                   Oid nameType) {
        this.principalName = principalName;
        this.nameType = nameType;
    }

    public PrincipalName toKerbyPrincipalName(sun.security.krb5.PrincipalName name) {
        return new PrincipalName(name.getNameString(), toKerbyNameType(name.getNameType()));
    }

    private NameType toKerbyNameType(int intNameType) {
        return NameType.fromValue(intNameType);
    }

    public static NameType toKerbyNameType(Oid nameType) throws GSSException {
        NameType kerbyNameType;

        if (nameType == null) {
            throw new GSSException(GSSException.BAD_NAMETYPE);
        }

        if (nameType.equals(GSSName.NT_EXPORT_NAME) || nameType.equals(GSSName.NT_USER_NAME)) {
            kerbyNameType = NameType.NT_PRINCIPAL;
        } else if (nameType.equals(GSSName.NT_HOSTBASED_SERVICE)) {
            kerbyNameType = NameType.NT_SRV_HST;
        } else {
            throw new GSSException(GSSException.BAD_NAMETYPE, 0, "Unsupported Oid name type");
        }
        return kerbyNameType;
    }

    public static GssNameElement getInstance(String name, Oid oidNameType)
            throws GSSException {
        PrincipalName principalName = new PrincipalName(name, toKerbyNameType(oidNameType));
        return new GssNameElement(principalName, oidNameType);
    }

    public Provider getProvider() {
        return new KerbyGssProvider();
    }

    public boolean equals(GSSNameSpi name) throws GSSException {
        if (name == null || name.isAnonymousName() || isAnonymousName()) {
            return false;
        }
        return this.toString().equals(name.toString()) && this.getStringNameType().equals(name.getStringNameType());
    }

    public final PrincipalName getPrincipalName() {
        return principalName;
    }

    public boolean equals(Object another) {
        if (another == null) {
            return false;
        }

        try {
            if (another instanceof GSSNameSpi) {
                return equals((GSSNameSpi) another);
            }
        } catch (GSSException e) {
            return false;
        }

        return false;
    }

    public int hashCode() {
        return principalName.hashCode();
    }

    public byte[] export() throws GSSException {
        byte[] retVal;
        try {
            retVal = principalName.getName().getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new GSSException(GSSException.BAD_NAME, -1, e.getMessage());
        }
        return retVal;
    }

    public Oid getMechanism() {
        return GssMechFactory.getOid();
    }

    public String toString() {
        return principalName.toString();
    }

    public Oid getStringNameType() {
        return nameType;
    }

    public boolean isAnonymousName() {
        return nameType.equals(GSSName.NT_ANONYMOUS);
    }
}
