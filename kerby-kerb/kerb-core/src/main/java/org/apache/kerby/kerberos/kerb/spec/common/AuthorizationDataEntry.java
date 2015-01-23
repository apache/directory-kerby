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
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public class AuthorizationDataEntry extends KrbSequenceType {
    private static int AD_TYPE = 0;
    private static int AD_DATA = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(AD_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(AD_DATA, 1, Asn1OctetString.class)
    };

    public AuthorizationDataEntry() {
        super(fieldInfos);
    }

    public AuthorizationType getAuthzType() {
        Integer value = getFieldAsInteger(AD_TYPE);
        return AuthorizationType.fromValue(value);
    }

    public void setAuthzType(AuthorizationType authzType) {
        setFieldAsInt(AD_TYPE, authzType.getValue());
    }

    public byte[] getAuthzData() {
        return getFieldAsOctets(AD_DATA);
    }

    public void setAuthzData(byte[] authzData) {
        setFieldAsOctets(AD_DATA, authzData);
    }
}
