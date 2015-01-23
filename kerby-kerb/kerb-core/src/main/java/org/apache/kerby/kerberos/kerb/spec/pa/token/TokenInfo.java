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
package org.apache.kerby.kerberos.kerb.spec.pa.token;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.asn1.type.Asn1Utf8String;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 TokenInfo ::= SEQUENCE {
    flags            [0] TokenFlags,
    tokenVendor      [1] UTF8String,
 }
 */
public class TokenInfo extends KrbSequenceType {
    private static int FLAGS = 0;
    private static int TOKEN_VENDOR = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(FLAGS, Asn1OctetString.class, true),
            new Asn1FieldInfo(TOKEN_VENDOR, Asn1Utf8String.class),
    };

    public TokenInfo() {
        super(fieldInfos);
    }

    public TokenFlags getFlags() {
        return getFieldAs(FLAGS, TokenFlags.class);
    }

    public void setFlags(TokenFlags flags) {
        setFieldAs(FLAGS, flags);
    }

    public String getTokenVendor() {
        return getFieldAsString(TOKEN_VENDOR);
    }

    public void setTokenVendor(String tokenVendor) {
        setFieldAs(TOKEN_VENDOR, new Asn1Utf8String(tokenVendor));
    }

}
