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

import java.net.InetAddress;
import java.util.Arrays;

import org.apache.kerby.asn1.Asn1FieldInfo;
import org.apache.kerby.asn1.EnumType;
import org.apache.kerby.asn1.ExplicitField;
import org.apache.kerby.asn1.type.Asn1Integer;
import org.apache.kerby.asn1.type.Asn1OctetString;
import org.apache.kerby.kerberos.kerb.type.KrbSequenceType;

/**
 * The HostAddress as defined in RFC 4120 :
 * <pre>
 * HostAddress     ::= SEQUENCE  {
 *         addr-type       [0] Int32,
 *         address         [1] OCTET STRING
 * }
 * </pre>
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class HostAddress extends KrbSequenceType {
    /**
     * The HostAddress fields
     */
    protected enum HostAddressField implements EnumType {
        ADDR_TYPE,
        ADDRESS;

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

    /** The HostAddress' fields */
    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new ExplicitField(HostAddressField.ADDR_TYPE, Asn1Integer.class),
            new ExplicitField(HostAddressField.ADDRESS, Asn1OctetString.class)
    };

    /**
     * Creates a new (empty) instance of HostAddress
     */
    public HostAddress() {
        super(fieldInfos);
    }

    /**
     * Creates a new instance of a HostAddress using an {@link InetAddress} 
     * @param inetAddress The {@link InetAddress} to use
     */
    public HostAddress(InetAddress inetAddress) {
        super(fieldInfos);

        setAddrType(HostAddrType.ADDRTYPE_INET);
        setAddress(inetAddress.getAddress());
    }

    /**
     * @return The HostAddrType for this instance
     */
    public HostAddrType getAddrType() {
        Integer value = getFieldAsInteger(HostAddressField.ADDR_TYPE);
        
        return HostAddrType.fromValue(value);
    }

    /**
     * Sets the AddressType
     * @param addrType The HostAddrType to set
     */
    public void setAddrType(HostAddrType addrType) {
        setField(HostAddressField.ADDR_TYPE, addrType);
    }

    /**
     * @return The HostAddress as a byte[]
     */
    public byte[] getAddress() {
        return getFieldAsOctets(HostAddressField.ADDRESS);
    }

    /**
     * Sets the address
     * 
     * @param address The address to use, as a byte[]
     */
    public void setAddress(byte[] address) {
        setFieldAsOctets(HostAddressField.ADDRESS, address);
    }

    /**
     * Compare a given {@link InetAddress} with the current HostAddress
     * @param address The {@link InetAddress} we want to compare with the HostAddress
     * @return <tt>true</tt> if they are equal
     */
    public boolean equalsWith(InetAddress address) {
        if (address == null) {
            return false;
        }
        
        HostAddress that = new HostAddress(address);
        
        return equals(that);
    }

    /**
     * @see Object#equals(Object)
     */
    @Override
    public boolean equals(Object other) {
        if (other == this) {
            return true;
        }
        
        if (!(other instanceof HostAddress)) {
            return false;
        }

        HostAddress that = (HostAddress) other;
        
        return getAddrType() == that.getAddrType()
                && Arrays.equals(getAddress(), that.getAddress());
    }

    /**
     * @see Object#hashCode()
     */
    @Override
    public int hashCode() {
        int hash = 17 + getAddrType().getValue() * 31;
        
        if (getAddress() != null) {
            hash = 31 * hash + Arrays.hashCode(getAddress());
        }

        return hash;
    }
}
