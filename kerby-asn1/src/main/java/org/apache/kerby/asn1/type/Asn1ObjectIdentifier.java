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
package org.apache.kerby.asn1.type;

import org.apache.kerby.asn1.UniversalTag;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * ASN1 object identifier.
 */
public class Asn1ObjectIdentifier extends Asn1Simple<String> {
    public Asn1ObjectIdentifier() {
        this(null);
    }

    public Asn1ObjectIdentifier(String value) {
        super(UniversalTag.OBJECT_IDENTIFIER, value);
    }

    @Override
    protected void toBytes() {
        byte[][] bytesArr = convert(getValue());
        int allLen = 0;
        for (byte[] bytes : bytesArr) {
            allLen += bytes.length;
        }
        ByteBuffer buffer = ByteBuffer.allocate(allLen);
        for (byte[] bytes : bytesArr) {
            buffer.put(bytes);
        }
        setBytes(buffer.array());
    }

    protected void toValue() {
        StringBuilder sb = new StringBuilder();

        byte[] bytes = getBytes();
        byte[][] bytesGroups = group(bytes);
        BigInteger[] coms = convert(bytesGroups);

        long first = coms[0].longValue();
        sb.append(first / 40).append('.');
        sb.append(first % 40);
        if (coms.length > 1) {
            sb.append('.');
        }

        for (int i = 1; i < coms.length; ++i) {
            sb.append(coms[i].toString());
            if (i != coms.length - 1) {
                sb.append('.');
            }
        }

        String value = sb.toString();
        setValue(value);
    }

    private BigInteger[] convert(byte[][] bytesGroups) {
        BigInteger[] comps = new BigInteger[bytesGroups.length];

        for (int i = 0; i < bytesGroups.length; ++i) {
            comps[i] = convert(bytesGroups[i]);
        }

        return comps;
    }

    private BigInteger convert(byte[] bytes) {
        BigInteger value = BigInteger.valueOf(bytes[0] & 0x7f);
        for (int i = 1; i < bytes.length; ++i) {
            value = value.shiftLeft(7);
            value = value.or(BigInteger.valueOf(bytes[i] & 0x7f));
        }

        return value;
    }

    /**
     * divide and group bytes together belonging to each component
     */
    private byte[][] group(byte[] bytes) {
        int count = 0, i, j;
        int[] countArr = new int[bytes.length]; // how many bytes for each group
        for (i = 0; i < countArr.length; ++i) {
            countArr[i] = 0;
        }

        for (j = 0, i = 0; i < bytes.length; ++i) {
            if ((bytes[i] & 0x80) != 0) {
                countArr[j]++;
            } else {
                countArr[j++]++;
            }
        }
        count = j;

        byte[][] bytesGroups = new byte[count][];
        for (i = 0; i < count; ++i) {
            bytesGroups[i] = new byte[countArr[i]];
        }

        int k = 0;
        for (j = 0, i = 0; i < bytes.length; ++i) {
            bytesGroups[j][k++] = bytes[i];
            if ((bytes[i] & 0x80) == 0) {
                j++;
                k = 0;
            }
        }

        return bytesGroups;
    }

    private byte[][] convert(String oid) {
        String[] parts = oid.split("\\.");
        BigInteger[] coms = new BigInteger[parts.length - 1];
        for (int i = 1; i < parts.length; ++i) {
            coms[i - 1] = new BigInteger(parts[i]);
        }
        coms[0] = coms[0].add(BigInteger.valueOf(Integer.parseInt(parts[0]) * 40));

        byte[][] bytesGroups = new byte[coms.length][];
        for (int i = 0; i < coms.length; ++i) {
            bytesGroups[i] = convert(coms[i]);
        }

        return bytesGroups;
    }

    private byte[] convert(BigInteger value) {
        int bitLen = value.bitLength();

        if (bitLen < 8) {
            return new byte[] {value.byteValue()};
        }

        int len = (bitLen + 6) / 7;
        byte[] bytes = new byte[len];
        BigInteger tmpValue = value;
        for (int i = len - 1; i >= 0; i--) {
            bytes[i] = (byte) ((tmpValue.byteValue() & 0x7f) | 0x80);
            tmpValue = tmpValue.shiftRight(7);
        }
        bytes[len - 1] &= 0x7f;

        return bytes;
    }
}
