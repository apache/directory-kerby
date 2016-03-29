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
 * The CheckSum as defined in RFC 4120 :
 * <pre>
 * Checksum        ::= SEQUENCE {
 *         cksumtype       [0] Int32,
 *         checksum        [1] OCTET STRING
 * }
 * </pre>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class CheckSum extends KrbSequenceType {
    /**
     * The CheckSum fields
     */
    protected enum CheckSumField implements EnumType {
        CKSUM_TYPE,
        CHECK_SUM;

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

    /** The Checksum's fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new ExplicitField(CheckSumField.CKSUM_TYPE, Asn1Integer.class),
        new ExplicitField(CheckSumField.CHECK_SUM, Asn1OctetString.class)
    };

    /**
     * Creates a new (empty) instance of Checksum
     */
    public CheckSum() {
        super(fieldInfos);
    }

    /**
     * Creates a new initialized instance of Checksum
     * 
     * @param cksumType The {@link CheckSumType}
     * @param checksum The checksum as a byte[]
     */
    public CheckSum(CheckSumType cksumType, byte[] checksum) {
        super(fieldInfos);

        setCksumtype(cksumType);
        setChecksum(checksum);
    }

    /**
     * Creates a new initialized instance of Checksum
     * 
     * @param cksumType The {@link CheckSumType} as an int
     * @param checksum The checksum as a byte[]
     */
    public CheckSum(int cksumType, byte[] checksum) {
        this(CheckSumType.fromValue(cksumType), checksum);
    }

    /**
     * @return The {@link CheckSumType} used for this instance
     */
    public CheckSumType getCksumtype() {
        Integer value = getFieldAsInteger(CheckSumField.CKSUM_TYPE);
        
        return CheckSumType.fromValue(value);
    }

    /**
     * Set the {@link CheckSumType}
     * 
     * @param cksumtype The {@link CheckSumType} to set
     */
    public void setCksumtype(CheckSumType cksumtype) {
        setFieldAsInt(CheckSumField.CKSUM_TYPE, cksumtype.getValue());
    }

    /**
     * @return The checksum
     */
    public byte[] getChecksum() {
        return getFieldAsOctets(CheckSumField.CHECK_SUM);
    }

    /**
     * Set the checksum in this instance
     * 
     * @param checksum The checksum to set
     */
    public void setChecksum(byte[] checksum) {
        setFieldAsOctets(CheckSumField.CHECK_SUM, checksum);
    }

    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }
        
        if (!(other instanceof CheckSum)) {
            return false;
        }

        CheckSum that = (CheckSum) other;

        return getCksumtype() == that.getCksumtype() && Arrays.equals(getChecksum(), that.getChecksum());
    }
    
    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode() {
        int result = 17;
        
        if (getCksumtype() != null) {
            result = 31 * result + getCksumtype().hashCode();
        }
        
        if (getChecksum() != null) {
            result = 31 * result + Arrays.hashCode(getChecksum());
        }
        
        return result;
    }

    /**
     * @param other The checksum to be compared
     * @return <tt>true</tt> if the given Checksum is equal to the instance
     */
    public boolean isEqual(CheckSum other) {
        return this.equals(other);
    }

    /**
     * Compare the checksum value of a given Checksum instance and this instance.
     *
     * @param cksumBytes The checksum bytes to be compared
     * @return <tt>true</tt> if the given CheckSum's checksum is equal to the instance's checksum
     */
    public boolean isEqual(byte[] cksumBytes) {
        return Arrays.equals(getChecksum(), cksumBytes);
    }
}
