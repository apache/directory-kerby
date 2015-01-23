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
package org.apache.kerby.token;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.asn1.type.Asn1SequenceType;

/**
 AuthorizationData       ::= SEQUENCE OF SEQUENCE {
     ad-type         [0] Int32,
     ad-data         [1] OCTET STRING
 }
 */
public class AuthzDataEntry extends Asn1SequenceType {
    static int AD_TYPE = 0;
    static int AD_DATA = 1;

    public AuthzDataEntry() {
        super(new Asn1FieldInfo[] {
                new Asn1FieldInfo(AD_TYPE, Asn1Integer.class),
                new Asn1FieldInfo(AD_DATA, Asn1OctetString.class)
        });
    }

    public int getAuthzType() {
        Integer value = getFieldAsInteger(AD_TYPE);
        return value;
    }

    public byte[] getAuthzData() {
        return getFieldAsOctets(AD_DATA);
    }
}
