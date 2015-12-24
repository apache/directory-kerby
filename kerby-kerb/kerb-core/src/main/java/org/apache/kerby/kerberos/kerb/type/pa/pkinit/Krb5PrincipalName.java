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
package org.apache.kerby.kerberos.kerb.type.pa.pkinit;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.type.base.PrincipalName;
import org.apache.kerby.kerberos.kerb.type.base.Realm;

/**
 KRB5PrincipalName ::= SEQUENCE {
     realm                   [0] Realm,
     principalName           [1] PrincipalName
 }
 */
public class Krb5PrincipalName extends KrbSequenceType {
    protected enum Krb5PrincipalNameField implements EnumType {
        REALM,
        PRINCIPAL_NAME;

        @Override
        public int getValue() {
            return ordinal();
        }

        @Override
        public String getName() {
            return name();
        }
    }

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(Krb5PrincipalNameField.REALM, Realm.class),
            new ExplicitField(Krb5PrincipalNameField.PRINCIPAL_NAME, PrincipalName.class)
    };

    public Krb5PrincipalName() {
        super(fieldInfos);
    }

    public String getRelm() {
        return getFieldAsString(Krb5PrincipalNameField.REALM);
    }

    public void setRealm(String realm) {
        setFieldAsString(Krb5PrincipalNameField.REALM, realm);
    }

    public PrincipalName getPrincipalName() {
        return getFieldAs(Krb5PrincipalNameField.PRINCIPAL_NAME, PrincipalName.class);
    }

    public void setPrincipalName(PrincipalName principalName) {
        setFieldAs(Krb5PrincipalNameField.PRINCIPAL_NAME, principalName);
    }
}
