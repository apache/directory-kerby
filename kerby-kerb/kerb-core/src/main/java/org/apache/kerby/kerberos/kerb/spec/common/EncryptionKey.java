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

import java.util.Arrays;

/**
 EncryptionKey   ::= SEQUENCE {
 keytype         [0] Int32 -- actually encryption type --,
 keyvalue        [1] OCTET STRING
 }
 */
public class EncryptionKey extends KrbSequenceType {
    private static int KEY_TYPE = 0;
    private static int KEY_VALUE = 1;

    private int kvno = -1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(KEY_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(KEY_VALUE, 1, Asn1OctetString.class)
    };

    public EncryptionKey() {
        super(fieldInfos);
    }

    public EncryptionKey(int keyType, byte[] keyData) {
        this(keyType, keyData, -1);
    }

    public EncryptionKey(int keyType, byte[] keyData, int kvno) {
        this(EncryptionType.fromValue(keyType), keyData, kvno);
    }

    public EncryptionKey(EncryptionType keyType, byte[] keyData) {
        this(keyType, keyData, -1);
    }

    public EncryptionKey(EncryptionType keyType, byte[] keyData, int kvno) {
        this();
        setKeyType(keyType);
        setKeyData(keyData);
        setKvno(kvno);
    }

    public EncryptionType getKeyType() {
        Integer value = getFieldAsInteger(KEY_TYPE);
        return EncryptionType.fromValue(value);
    }

    public void setKeyType(EncryptionType keyType) {
        setFieldAsInt(KEY_TYPE, keyType.getValue());
    }

    public byte[] getKeyData() {
        return getFieldAsOctets(KEY_VALUE);
    }

    public void setKeyData(byte[] keyData) {
        setFieldAsOctets(KEY_VALUE, keyData);
    }

    public void setKvno(int kvno) {
        this.kvno = kvno;
    }

    public int getKvno() {
        return kvno;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        EncryptionKey that = (EncryptionKey) o;

        if (kvno != -1 && that.kvno != -1 && kvno != that.kvno) return false;

        if (getKeyType() != that.getKeyType()) return false;

        return Arrays.equals(getKeyData(), that.getKeyData());
    }
}
