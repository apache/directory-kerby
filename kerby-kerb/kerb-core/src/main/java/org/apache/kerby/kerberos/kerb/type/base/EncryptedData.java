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
 * The EncryptedData structure, as defined in RFC 4120 :
 * <pre>
 *  EncryptedData   ::= SEQUENCE {
 *          etype   [0] Int32 -- EncryptionType --,
 *          kvno    [1] UInt32 OPTIONAL,
 *          cipher  [2] OCTET STRING -- ciphertext
 *  }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class EncryptedData extends KrbSequenceType {
    /**
     * The possible fields
     */
    protected enum EncryptedDataField implements EnumType {
        ETYPE,
        KVNO,
        CIPHER;

        /**
         * {@inheritDoc}
         */
        @Override
        public int getValue() {
            return ordinal();
        }

        /**
         * {@inheritDoc}
         */
        @Override
        public String getName() {
            return name();
        }
    }

    /** The EncryptedData's fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(EncryptedDataField.ETYPE, Asn1Integer.class),
            new ExplicitField(EncryptedDataField.KVNO, Asn1Integer.class),
            new ExplicitField(EncryptedDataField.CIPHER, Asn1OctetString.class)
    };

    /**
     * Creates an instance of EncryptedData
     */
    public EncryptedData() {
        super(fieldInfos);
    }

    /**
     * @return The {@link EncryptionType} of this instance
     */
    public EncryptionType getEType() {
        Integer value = getFieldAsInteger(EncryptedDataField.ETYPE);
        
        return EncryptionType.fromValue(value);
    }

    /**
     * Sets the {@link EncryptionType} value
     * 
     * @param eType the {@link EncryptionType} value to store
     */
    public void setEType(EncryptionType eType) {
        setFieldAsInt(EncryptedDataField.ETYPE, eType.getValue());
    }

    /**
     * @return The KVNO for this instance
     */
    public int getKvno() {
        Integer value = getFieldAsInteger(EncryptedDataField.KVNO);
        
        if (value != null) {
            return value.intValue();
        }
        
        return -1;
    }

    /**
     * Sets the instance's KVNO
     * 
     * @param kvno The KVNO for this instance
     */
    public void setKvno(int kvno) {
        setFieldAsInt(EncryptedDataField.KVNO, kvno);
    }

    /**
     * @return The Cipher stored in this instance
     */
    public byte[] getCipher() {
        return getFieldAsOctets(EncryptedDataField.CIPHER);
    }

    /**
     * Sets the Cipher in this instance
     * 
     * @param cipher The Cipher to store
     */
    public void setCipher(byte[] cipher) {
        setFieldAsOctets(EncryptedDataField.CIPHER, cipher);
    }

    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        
        if (!(o instanceof EncryptedData)) {
            return false;
        }
        
        EncryptedData that = (EncryptedData) o;

        return getEType() == that.getEType() && Arrays.equals(getCipher(), that.getCipher());
    }
    
    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode() {
        int result = 17;
        
        if (getEType() != null) {
            result = 31 * result + getEType().hashCode();
        }
        
        if (getCipher() != null) {
            result = 31 * result + Arrays.hashCode(getCipher());
        }
        
        return result;
    }
}
