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
package org.apache.kerby.kerberos.kerb.spec.pa.otp;

import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.asn1.type.Asn1Utf8String;
import org.apache.kerby.kerberos.kerb.spec.KerberosString;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 PA-OTP-CHALLENGE ::= SEQUENCE {
     nonce            [0] OCTET STRING,
     otp-service      [1] UTF8String               OPTIONAL,
     otp-tokenInfo    [2] SEQUENCE (SIZE(1..MAX)) OF OTP-TOKENINFO,
     salt             [3] KerberosString           OPTIONAL,
     s2kparams        [4] OCTET STRING             OPTIONAL,
 }
 */
public class PaOtpChallenge extends KrbSequenceType {
    private static int NONCE = 0;
    private static int OTP_SERVICE = 1;
    private static int OTP_TOKEN_INFO = 2;
    private static int SALT = 3;
    private static int S2KPARAMS = 4;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(NONCE, Asn1OctetString.class, true),
            new Asn1FieldInfo(OTP_SERVICE, Asn1Utf8String.class),
            new Asn1FieldInfo(OTP_TOKEN_INFO, Asn1OctetString.class, true),
            new Asn1FieldInfo(SALT, KerberosString.class),
            new Asn1FieldInfo(S2KPARAMS, Asn1OctetString.class, true)
    };

    public PaOtpChallenge() {
        super(fieldInfos);
    }
}
