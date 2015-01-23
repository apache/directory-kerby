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
package org.apache.kerby.kerberos.kerb.spec.pa.pkinit;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;
import org.apache.kerby.kerberos.kerb.spec.common.PrincipalName;
import org.apache.kerby.kerberos.kerb.spec.common.Realm;

/**
 KRB5PrincipalName ::= SEQUENCE {
     realm                   [0] Realm,
     principalName           [1] PrincipalName
 }
 */
public class Krb5PrincipalName extends KrbSequenceType {
    private static int REALM = 0;
    private static int PRINCIPAL_NAME = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(REALM, Realm.class),
            new Asn1FieldInfo(PRINCIPAL_NAME, PrincipalName.class)
    };

    public Krb5PrincipalName() {
        super(fieldInfos);
    }

    public String getRelm() {
        return getFieldAsString(REALM);
    }

    public void setRealm(String realm) {
        setFieldAsString(REALM, realm);
    }

    public PrincipalName getPrincipalName() {
        return getFieldAs(PRINCIPAL_NAME, PrincipalName.class);
    }

    public void setPrincipalName(PrincipalName principalName) {
        setFieldAs(PRINCIPAL_NAME, principalName);
    }
}
