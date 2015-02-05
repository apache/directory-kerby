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
package org.apache.kerby.kerberos.kerb.spec.common;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.spec.KerberosStrings;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 PrincipalName   ::= SEQUENCE {
 name-type       [0] Int32,
 name-string     [1] SEQUENCE OF KerberosString
 }
 */
public class PrincipalName extends KrbSequenceType {
    private String realm;

    private static int NAME_TYPE = 0;
    private static int NAME_STRING = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(NAME_TYPE, Asn1Integer.class),
            new Asn1FieldInfo(NAME_STRING, KerberosStrings.class)
    };

    public PrincipalName() {
        super(fieldInfos);
    }

    public PrincipalName(String nameString) {
        this();
        setNameType(NameType.NT_PRINCIPAL);
        fromNameString(nameString);
    }

    public PrincipalName(List<String> nameStrings, NameType type) {
        this();
        setNameStrings(nameStrings);
        setNameType(type);
    }

    public NameType getNameType() {
        Integer value = getFieldAsInteger(NAME_TYPE);
        return NameType.fromValue(value);
    }

    public void setNameType(NameType nameType) {
        setFieldAsInt(NAME_TYPE, nameType.getValue());
    }

    public List<String> getNameStrings() {
        KerberosStrings krbStrings = getFieldAs(NAME_STRING, KerberosStrings.class);
        if (krbStrings != null) {
            return krbStrings.getAsStrings();
        }
        return Collections.emptyList();
    }

    public void setNameStrings(List<String> nameStrings) {
        setFieldAs(NAME_STRING, new KerberosStrings(nameStrings));
    }

    public void setRealm(String realm) {
        this.realm = realm;
    }

    public String getRealm() {
        return this.realm;
    }

    public String getName() {
        return makeSingleName();
    }

    private String makeSingleName() {
        List<String> names = getNameStrings();
        StringBuilder sb = new StringBuilder();
        boolean isFirst = true;
        for (String name : names) {
            sb.append(name);
            if (isFirst && names.size() > 1) {
                sb.append('/');
            }
            isFirst = false;
        }

        String realm = getRealm();
        if (realm != null && !realm.isEmpty()) {
            sb.append('@');
            sb.append(realm);
        }

        return sb.toString();
    }

    @Override
    public String toString() {
        return getName();
    }

    @Override
    public int hashCode() {
        return getName().hashCode();
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        } else if (this == other) {
            return true;
        } else if (other instanceof String) {
            String otherPrincipal = (String) other;
            String thisPrincipal = getName();
            return thisPrincipal.equals(otherPrincipal);
        } else if (! (other instanceof PrincipalName)) {
            return false;
        }

        PrincipalName otherPrincipal = (PrincipalName) other;
        if (getNameType() != ((PrincipalName) other).getNameType()) {
            return false;
        }

        return getName().equals(otherPrincipal.getName());
    }

    private void fromNameString(String nameString) {
        String tmpRealm = null;
        List<String> nameStrings;
        int pos = nameString.indexOf('@');
        String nameParts = nameString;
        if (pos != -1) {
            nameParts = nameString.substring(0, pos);
            tmpRealm = nameString.substring(pos + 1);
        }
        String parts[] = nameParts.split("\\/");
        nameStrings = Arrays.asList(parts);

        setNameStrings(nameStrings);
        setRealm(tmpRealm);
    }

    public static String extractRealm(String principal) {
        int pos = principal.indexOf('@');

        if (pos > 0) {
            return principal.substring(pos + 1);
        }

        throw new IllegalArgumentException("Not a valid principal, missing realm name");
    }


    public static String extractName(String principal) {
        int pos = principal.indexOf('@');

        if (pos < 0) {
            return principal;
        }

        return principal.substring(0, pos);
    }

    public static String makeSalt(PrincipalName principalName) {
        StringBuilder salt = new StringBuilder();
        if (principalName.getRealm() != null) {
            salt.append(principalName.getRealm().toString());
        }
        List<String> nameStrings = principalName.getNameStrings();
        for (String ns : nameStrings) {
            salt.append(ns);
        }
        return salt.toString();
    }

}
