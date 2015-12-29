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

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1BitString;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.kerberos.kerb.type.KerberosTime;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 KDCDHKeyInfo ::= SEQUENCE {
    subjectPublicKey        [0] BIT STRING,
    nonce                   [1] INTEGER (0..4294967295),
    dhKeyExpiration         [2] KerberosTime OPTIONAL,
 }
 */
public class KdcDhKeyInfo extends KrbSequenceType {
    protected enum KdcDhKeyInfoField implements EnumType {
        SUBJECT_PUBLIC_KEY,
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
            new ExplicitField(KdcDhKeyInfoField.SUBJECT_PUBLIC_KEY, Asn1BitString.class),
            new ExplicitField(KdcDhKeyInfoField.NONCE, Asn1Integer.class),
            new ExplicitField(KdcDhKeyInfoField.DH_KEY_EXPIRATION, KerberosTime.class)
    };

    public KdcDhKeyInfo() {
        super(fieldInfos);
    }

    public Asn1BitString getSubjectPublicKey() {
        return getFieldAs(KdcDhKeyInfoField.SUBJECT_PUBLIC_KEY, Asn1BitString.class);
    }

    public void setSubjectPublicKey(byte[] subjectPubKey) {
        setFieldAs(KdcDhKeyInfoField.SUBJECT_PUBLIC_KEY, new Asn1BitString(subjectPubKey));
    }

    public int getNonce() {
        return getFieldAsInt(KdcDhKeyInfoField.NONCE);
    }

    public void setNonce(int nonce) {
        setFieldAsInt(KdcDhKeyInfoField.NONCE, nonce);
    }

    public KerberosTime getDHKeyExpiration() {
        return getFieldAsTime(KdcDhKeyInfoField.DH_KEY_EXPIRATION);
    }

    public void setDHKeyExpiration(KerberosTime time) {
        setFieldAs(KdcDhKeyInfoField.DH_KEY_EXPIRATION, time);
    }
}
