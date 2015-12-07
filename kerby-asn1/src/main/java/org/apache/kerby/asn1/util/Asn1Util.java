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
package org.apache.kerby.asn1.util;

import org.apache.kerby.asn1.Tag;

import java.nio.ByteBuffer;

/**
 * The abstract ASN1 object for all the ASN1 types. It provides basic
 * encoding and decoding utilities.
 */
public final class Asn1Util {
    private Asn1Util() {
        
    }

    public static int lengthOfBodyLength(int bodyLength) {
        int length = 1;

        if (bodyLength > 127) {
            int payload = bodyLength;
            while (payload != 0) {
                payload >>= 8;
                length++;
            }
        }

        return length;
    }

    public static int lengthOfTagLength(int tagNo) {
        int length = 1;

        if (tagNo >= 31) {
            if (tagNo < 128) {
                length++;
            } else {
                length++;

                do {
                    tagNo >>= 7;
                    length++;
                } while (tagNo > 127);
            }
        }

        return length;
    }

    public static void encodeTag(ByteBuffer buffer, Tag tag) {
        int flags = tag.tagFlags();
        int tagNo = tag.tagNo();

        if (tagNo < 31) {
            buffer.put((byte) (flags | tagNo));
        } else {
            buffer.put((byte) (flags | 0x1f));
            if (tagNo < 128) {
                buffer.put((byte) tagNo);
            } else {
                byte[] tmpBytes = new byte[5]; // 5 * 7 > 32
                int iPut = tmpBytes.length;

                tmpBytes[--iPut] = (byte) (tagNo & 0x7f);
                do {
                    tagNo >>= 7;
                    tmpBytes[--iPut] = (byte) (tagNo & 0x7f | 0x80);
                } while (tagNo > 127);

                buffer.put(tmpBytes, iPut, tmpBytes.length - iPut);
            }
        }
    }

    public static void encodeLength(ByteBuffer buffer, int bodyLength) {
        if (bodyLength < 128) {
            buffer.put((byte) bodyLength);
        } else {
            int length = 0;
            int payload = bodyLength;

            while (payload != 0) {
                payload >>= 8;
                length++;
            }

            buffer.put((byte) (length | 0x80));

            payload = bodyLength;
            for (int i = length - 1; i >= 0; i--) {
                buffer.put((byte) (payload >> (i * 8)));
            }
        }
    }

    public static byte[] readAllLeftBytes(ByteBuffer buffer) {
        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        return result;
    }
}
