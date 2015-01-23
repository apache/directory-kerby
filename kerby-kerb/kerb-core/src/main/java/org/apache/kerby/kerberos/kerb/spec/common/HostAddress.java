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

import java.net.InetAddress;
import java.util.Arrays;

/*
HostAddress     ::= SEQUENCE  {
        addr-type       [0] Int32,
        address         [1] OCTET STRING
}
 */
public class HostAddress extends KrbSequenceType {
    private static int ADDR_TYPE = 0;
    private static int ADDRESS = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
            new Asn1FieldInfo(ADDR_TYPE, 0, Asn1Integer.class),
            new Asn1FieldInfo(ADDRESS, 1, Asn1OctetString.class)
    };

    public HostAddress() {
        super(fieldInfos);
    }

    public HostAddress(InetAddress inetAddress) {
        this();

        setAddrType(HostAddrType.ADDRTYPE_INET);
        setAddress(inetAddress.getAddress());
    }

    public HostAddrType getAddrType() {
        Integer value = getFieldAsInteger(ADDR_TYPE);
        return HostAddrType.fromValue(value);
    }

    public void setAddrType(HostAddrType addrType) {
        setField(ADDR_TYPE, addrType);
    }

    public byte[] getAddress() {
        return getFieldAsOctets(ADDRESS);
    }

    public void setAddress(byte[] address) {
        setFieldAsOctets(ADDRESS, address);
    }

    public boolean equalsWith(InetAddress address) {
        if (address == null) {
            return false;
        }
        HostAddress that = new HostAddress(address);
        return that.equals(this);
    }

    @Override
    public boolean equals(Object other) {
        if (other == null) {
            return false;
        }
        if (other == this) {
            return true;
        } else if (! (other instanceof HostAddress)) {
            return false;
        }

        HostAddress that = (HostAddress) other;
        if (getAddrType() == that.getAddrType() &&
                Arrays.equals(getAddress(), that.getAddress())) {
            return true;
        }
        return false;
    }

    @Override
    public int hashCode() {
        int result = getAddrType().getValue();
        if (getAddress() != null) {
            result = 31 * result + getAddress().hashCode();
        }

        return result;
    }
}
