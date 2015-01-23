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
package org.apache.kerby.kerberos.kerb.spec.pa;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 PA-AUTHENTICATION-SET-ELEM ::= SEQUENCE {
     pa-type      [0] Int32,
     -- same as padata-type.
     pa-hint      [1] OCTET STRING OPTIONAL,
     pa-value     [2] OCTET STRING OPTIONAL
 }
 */
public class PaAuthenticationSetElem extends KrbSequenceType {
    private static int PA_TYPE = 0;
    private static int PA_HINT = 1;
    private static int PA_VALUE = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PA_TYPE, Asn1Integer.class),
            new Asn1FieldInfo(PA_HINT, Asn1OctetString.class),
            new Asn1FieldInfo(PA_VALUE, Asn1OctetString.class)
    };

    public PaAuthenticationSetElem() {
        super(fieldInfos);
    }

    public PaDataType getPaType() {
        Integer value = getFieldAsInteger(PA_TYPE);
        return PaDataType.fromValue(value);
    }

    public void setPaType(PaDataType paDataType) {
        setFieldAsInt(PA_TYPE, paDataType.getValue());
    }

    public byte[] getPaHint() {
        return getFieldAsOctets(PA_HINT);
    }

    public void setPaHint(byte[] paHint) {
        setFieldAsOctets(PA_HINT, paHint);
    }

    public byte[] getPaValue() {
        return getFieldAsOctets(PA_VALUE);
    }

    public void setPaValue(byte[] paDataValue) {
        setFieldAsOctets(PA_VALUE, paDataValue);
    }
}
