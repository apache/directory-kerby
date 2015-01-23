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
 TransitedEncoding       ::= SEQUENCE {
 tr-type         [0] Int32 -- must be registered --,
 contents        [1] OCTET STRING
 }
 */
public class TransitedEncoding extends KrbSequenceType {
    private static int TR_TYPE = 0;
    private static int CONTENTS = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(TR_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(CONTENTS, 1, Asn1OctetString.class)
    };

    public TransitedEncoding() {
        super(fieldInfos);
    }

    public TransitedEncodingType getTrType() {
        Integer value = getFieldAsInteger(TR_TYPE);
        return TransitedEncodingType.fromValue(value);
    }

    public void setTrType(TransitedEncodingType trType) {
        setField(TR_TYPE, trType);
    }

    public byte[] getContents() {
        return getFieldAsOctets(CONTENTS);
    }

    public void setContents(byte[] contents) {
        setFieldAsOctets(CONTENTS, contents);
    }
}
