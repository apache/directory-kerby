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
package org.apache.kerby.kerberos.kerb.type.base;

import java.util.Arrays;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 EncryptedData   ::= SEQUENCE {
 etype   [0] Int32 -- EncryptionType --,
 kvno    [1] UInt32 OPTIONAL,
 cipher  [2] OCTET STRING -- ciphertext
 }
 */
public class EncryptedData extends KrbSequenceType {
    protected enum EncryptedDataField implements EnumType {
        ETYPE,
        KVNO,
        CIPHER;

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
            new ExplicitField(EncryptedDataField.ETYPE, Asn1Integer.class),
            new ExplicitField(EncryptedDataField.KVNO, Asn1Integer.class),
            new ExplicitField(EncryptedDataField.CIPHER, Asn1OctetString.class)
    };

    public EncryptedData() {
        super(fieldInfos);
    }

    public EncryptionType getEType() {
        Integer value = getFieldAsInteger(EncryptedDataField.ETYPE);
        return EncryptionType.fromValue(value);
    }

    public void setEType(EncryptionType eType) {
        setFieldAsInt(EncryptedDataField.ETYPE, eType.getValue());
    }

    public int getKvno() {
        Integer value = getFieldAsInteger(EncryptedDataField.KVNO);
        if (value != null) {
            return value.intValue();
        }
        return -1;
    }

    public void setKvno(int kvno) {
        setFieldAsInt(EncryptedDataField.KVNO, kvno);
    }

    public byte[] getCipher() {
        return getFieldAsOctets(EncryptedDataField.CIPHER);
    }

    public void setCipher(byte[] cipher) {
        setFieldAsOctets(EncryptedDataField.CIPHER, cipher);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }

        EncryptedData that = (EncryptedData) o;

        /*
        if (getKvno() != -1 && that.getKvno() != -1 &&
                getKvno() != that.getKvno()) return false;
        */

        if (getEType() != that.getEType()) {
            return false;
        }

        return Arrays.equals(getCipher(), that.getCipher());
    }
    
    @Override
    public int hashCode() {
        int result = 0;
        if (getEType() != null) {
            result = 31 * result + getEType().hashCode();
        }
        if (getCipher() != null) {
            result = 31 * result + Arrays.hashCode(getCipher());
        }
        return result;
    }
}
