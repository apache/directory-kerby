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
package org.apache.kerby.kerberos.kerb.spec.pa.pkinit;

import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1FieldInfo;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.spec.KerberosTime;
import org.apache.kerby.kerberos.kerb.spec.KrbSequenceType;

/**
 KDCDHKeyInfo ::= SEQUENCE {
    subjectPublicKey        [0] BIT STRING,
    nonce                   [1] INTEGER (0..4294967295),
    dhKeyExpiration         [2] KerberosTime OPTIONAL,
 }
 */
public class KdcDHKeyInfo extends KrbSequenceType {
    private static int SUBJECT_PUBLICK_KEY = 0;
    private static int NONCE = 1;
    private static int DH_KEY_EXPIRATION = 2;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(SUBJECT_PUBLICK_KEY, Asn1BitString.class),
            new Asn1FieldInfo(NONCE, Asn1Integer.class),
            new Asn1FieldInfo(DH_KEY_EXPIRATION, KerberosTime.class)
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
