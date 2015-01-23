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
 Checksum        ::= SEQUENCE {
 cksumtype       [0] Int32,
 checksum        [1] OCTET STRING
 }
 */
public class CheckSum extends KrbSequenceType {
    private static int CKSUM_TYPE = 0;
    private static int CHECK_SUM = 1;

    static Asn1FieldInfo[] fieldInfos = new Asn1FieldInfo[] {
        new Asn1FieldInfo(CKSUM_TYPE, 0, Asn1Integer.class),
        new Asn1FieldInfo(CHECK_SUM, 1, Asn1OctetString.class)
    };

    public CheckSum() {
        super(fieldInfos);
    }

    public CheckSum(CheckSumType cksumType, byte[] checksum) {
        this();

        setCksumtype(cksumType);
        setChecksum(checksum);
    }

    public CheckSum(int cksumType, byte[] checksum) {
        this(CheckSumType.fromValue(cksumType), checksum);
    }

    public CheckSumType getCksumtype() {
        Integer value = getFieldAsInteger(CKSUM_TYPE);
        return CheckSumType.fromValue(value);
    }

    public void setCksumtype(CheckSumType cksumtype) {
        setFieldAsInt(CKSUM_TYPE, cksumtype.getValue());
    }

    public byte[] getChecksum() {
        return getFieldAsOctets(CHECK_SUM);
    }

    public void setChecksum(byte[] checksum) {
        setFieldAsOctets(CHECK_SUM, checksum);
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) return true;
        if (other == null || getClass() != other.getClass()) return false;

        CheckSum that = (CheckSum) other;

        if (getCksumtype() != that.getCksumtype()) return false;

        return Arrays.equals(getChecksum(), that.getChecksum());
    }

    public boolean isEqual(CheckSum other) {
        return this.equals(other);
    }

    public boolean isEqual(byte[] cksumBytes) {
        return Arrays.equals(getChecksum(), cksumBytes);
    }
}
