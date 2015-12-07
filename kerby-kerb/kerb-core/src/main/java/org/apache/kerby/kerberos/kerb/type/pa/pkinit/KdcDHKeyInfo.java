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
package org.apache.kerby.kerberos.kerb.type.pa.pkinit;

import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;
import static org.apache.kerby.kerberos.kerb.type.pa.pkinit.KdcDHKeyInfo.MyEnum.*;

/**
 KDCDHKeyInfo ::= SEQUENCE {
    subjectPublicKey        [0] BIT STRING,
    nonce                   [1] INTEGER (0..4294967295),
    dhKeyExpiration         [2] KerberosTime OPTIONAL,
 }
 */
public class KdcDHKeyInfo extends KrbSequenceType {
    protected enum MyEnum implements EnumType {
        SUBJECT_PUBLICK_KEY,
        NONCE,
        DH_KEY_EXPIRATION;

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
            new ExplicitField(SUBJECT_PUBLICK_KEY, Asn1BitString.class),
            new ExplicitField(NONCE, Asn1Integer.class),
            new ExplicitField(DH_KEY_EXPIRATION, KerberosTime.class)
    };

    public KdcDHKeyInfo() {
        super(fieldInfos);
    }

    public byte[] getSubjectPublicKey() {
        return getFieldAsOctets(SUBJECT_PUBLICK_KEY);
    }

    public void setSubjectPublicKey(byte[] subjectPublicKey) {
        setFieldAsOctets(SUBJECT_PUBLICK_KEY, subjectPublicKey);
    }

    public int getNonce() {
        return getFieldAsInt(NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(NONCE, nonce);
    }
}
