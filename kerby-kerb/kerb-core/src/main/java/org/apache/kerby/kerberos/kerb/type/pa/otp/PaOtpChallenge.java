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
package org.apache.kerby.kerberos.kerb.type.pa.otp;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.asn1.type.Asn1Utf8String;
import org.apache.kerby.kerberos.kerb.type.KerberosString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

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
    protected enum PaOtpChallengeField implements EnumType {
        NONCE,
        OTP_SERVICE,
        OTP_TOKEN_INFO,
        SALT,
        S2KPARAMS;

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
            new ExplicitField(PaOtpChallengeField.NONCE, Asn1OctetString.class),
            new ExplicitField(PaOtpChallengeField.OTP_SERVICE, Asn1Utf8String.class),
            new ExplicitField(PaOtpChallengeField.OTP_TOKEN_INFO, Asn1OctetString.class),
            new ExplicitField(PaOtpChallengeField.SALT, KerberosString.class),
            new ExplicitField(PaOtpChallengeField.S2KPARAMS, Asn1OctetString.class)
    };

    public PaOtpChallenge() {
        super(fieldInfos);
    }
}
