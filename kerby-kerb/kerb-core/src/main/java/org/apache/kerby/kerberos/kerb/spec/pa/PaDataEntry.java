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
 PA-DATA         ::= SEQUENCE {
     -- NOTE: first tag is [1], not [0]
     padata-type     [1] Int32,
     padata-value    [2] OCTET STRING -- might be encoded AP-REQ
 }
 */
public class PaDataEntry extends KrbSequenceType {
    private static int PADATA_TYPE = 0;
    private static int PADATA_VALUE = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(PADATA_TYPE, 1, Asn1Integer.class),
            new Asn1FieldInfo(PADATA_VALUE, 2, Asn1OctetString.class)
    };

    public PaDataEntry() {
        super(fieldInfos);
    }

    public PaDataEntry(PaDataType type, byte[] paData) {
        this();
        setPaDataType(type);
        setPaDataValue(paData);
    }

    public PaDataType getPaDataType() {
        Integer value = getFieldAsInteger(PADATA_TYPE);
        return PaDataType.fromValue(value);
    }

    public void setPaDataType(PaDataType paDataType) {
        setFieldAsInt(PADATA_TYPE, paDataType.getValue());
    }

    public byte[] getPaDataValue() {
        return getFieldAsOctets(PADATA_VALUE);
    }

    public void setPaDataValue(byte[] paDataValue) {
        setFieldAsOctets(PADATA_VALUE, paDataValue);
    }
}
