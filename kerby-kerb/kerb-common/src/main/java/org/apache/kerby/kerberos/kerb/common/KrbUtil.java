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
package org.apache.kerby.kerberos.kerb.common;

import org.apache.kerby.kerberos.kerb.KrbConstant;
import org.apache.kerby.kerberos.kerb.KrbException;
import org.apache.kerby.kerberos.kerb.type.base.NameType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;

public class KrbUtil {

    public static final String ANONYMOUS_PRINCIPAL = "ANONYMOUS@WELLKNOWN:ANONYMOUS";
    /** First component of NT_WELLKNOWN principals */
    public static final String KRB5_WELLKNOWN_NAMESTR = "WELLKNOWN";
    public static final String KRB5_ANONYMOUS_PRINCSTR = "ANONYMOUS";
    public static final String KRB5_ANONYMOUS_REALMSTR = "WELLKNOWN:ANONYMOUS";

    /**
     * Construct TGS principal name.
     * @param realm The realm
     * @return principal
     */
    public static PrincipalName makeTgsPrincipal(String realm) {
        String nameString = KrbConstant.TGS_PRINCIPAL + "/" + realm + "@" + realm;
        return new PrincipalName(nameString, NameType.NT_SRV_INST);
    }

    /**
     * Construct kadmin principal name.
     * @param realm The realm
     * @return principal
     */
    public static PrincipalName makeKadminPrincipal(String realm) {
        String nameString = "kadmin/" + realm + "@" + realm;
        return new PrincipalName(nameString, NameType.NT_PRINCIPAL);
    }

    /**
     * Construct the kadmin principal
     * @param principal The principal name
     * @param realm The realm
     * @return principal
     */
    public static PrincipalName makeKadminPrincipal(String principal, String realm) {
        String nameString = principal + "@" + realm;
        return new PrincipalName(nameString, NameType.NT_PRINCIPAL);
    }

    public static boolean pricipalCompareIgnoreRealm(PrincipalName princ1, PrincipalName princ2)
            throws KrbException {

        if (princ1 != null && princ2 != null) {
            princ1.setRealm(null);
            princ2.setRealm(null);
            if (princ1.getName().equals(princ2.getName())) {
                return true;
            } else {
                return false;
            }
        } else {
            throw new KrbException("principal can't be null.");
        }
    }

    public static PrincipalName makeAnonymousPrincipal() {
        PrincipalName principalName = new PrincipalName(KRB5_WELLKNOWN_NAMESTR + "/" + KRB5_ANONYMOUS_PRINCSTR);
        principalName.setRealm(KRB5_ANONYMOUS_REALMSTR);
        principalName.setNameType(NameType.NT_WELLKNOWN);
        return principalName;
    }
}
