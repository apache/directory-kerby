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
package org.apache.kerby.kerberos.kerb.type.ad;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
 ad-type         [0] Int32,
 ad-data         [1] OCTET STRING
 }
 */
public class AuthorizationDataEntry extends KrbSequenceType {
    protected enum AuthorizationDataEntryField implements EnumType {
        AD_TYPE,
        AD_DATA;

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
            new ExplicitField(AuthorizationDataEntryField.AD_TYPE, Asn1Integer.class),
            new ExplicitField(AuthorizationDataEntryField.AD_DATA, Asn1OctetString.class)
    };

    public AuthorizationDataEntry() {
        super(fieldInfos);
    }

    public AuthorizationType getAuthzType() {
        Integer value = getFieldAsInteger(AuthorizationDataEntryField.AD_TYPE);
        return AuthorizationType.fromValue(value);
    }

    public void setAuthzType(AuthorizationType authzType) {
        setFieldAsInt(AuthorizationDataEntryField.AD_TYPE, authzType.getValue());
    }

    public byte[] getAuthzData() {
        return getFieldAsOctets(AuthorizationDataEntryField.AD_DATA);
    }

    public void setAuthzData(byte[] authzData) {
        setFieldAsOctets(AuthorizationDataEntryField.AD_DATA, authzData);
    }
}
