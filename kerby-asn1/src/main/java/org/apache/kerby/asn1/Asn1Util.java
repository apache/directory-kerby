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
package org.apache.kerby.asn1;

import java.io.IOException;
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

    public static Tag readTag(ByteBuffer buffer) throws IOException {
        int tagFlags = readTagFlags(buffer);
        int tagNo = readTagNo(buffer, tagFlags);
        return new Tag(tagFlags, tagNo);
    }

    private static int readTagFlags(ByteBuffer buffer) throws IOException {
        int tagFlags = buffer.get() & 0xff;
        if (tagFlags == 0) {
            throw new IOException("Bad tag 0 found");
        }
        return tagFlags;
    }

    private static int readTagNo(ByteBuffer buffer, int tagFlags) throws IOException {
        int tagNo = tagFlags & 0x1f;

        if (tagNo == 0x1f) {
            tagNo = 0;

            int b = buffer.get() & 0xff;
            if ((b & 0x7f) == 0) {
                throw new IOException("Invalid high tag number found");
            }

            while (b >= 0 && (b & 0x80) != 0) {
                tagNo |= b & 0x7f;
                tagNo <<= 7;
                b = buffer.get();
            }

            tagNo |= b & 0x7f;
        }

        return tagNo;
    }

    public static int readLength(ByteBuffer buffer) throws IOException {
        int result = buffer.get() & 0xff;
        if (result == 0x80) {
            return -1; // non-definitive length
        }

        if (result > 127) {
            int length = result & 0x7f;
            if (length > 4) {
                throw new IOException("Bad length of more than 4 bytes: " + length);
            }

            result = 0;
            int tmp;
            for (int i = 0; i < length; i++) {
                tmp = buffer.get() & 0xff;
                result = (result << 8) + tmp;
            }
        }

        if (result < 0) {
            throw new IOException("Invalid length " + result);
        }

        if (result > buffer.remaining()) {
            throw new IOException("Corrupt stream - less data "
                + buffer.remaining() + " than expected " + result);
        }

        return result;
    }

    public static ByteBuffer dupWithLength(ByteBuffer buffer, int length) {
        try {
            ByteBuffer result = buffer.duplicate();
            result.limit(buffer.position() + length);
            buffer.position(buffer.position() + length);
            return result;
        } catch (Exception e) {
            throw e;
        }
    }

    public static byte[] readAllLeftBytes(ByteBuffer buffer) {
        byte[] result = new byte[buffer.remaining()];
        buffer.get(result);
        return result;
    }
}
