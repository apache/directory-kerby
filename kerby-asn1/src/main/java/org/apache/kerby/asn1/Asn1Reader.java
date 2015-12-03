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
 * ASN1 reader from a byte buffer.
 */
public abstract class Asn1Reader {
    protected ByteBuffer buffer;

    public Asn1Reader(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    public ByteBuffer getBuffer() {
        return buffer;
    }

    public Asn1Header readHeader() throws IOException {
        Tag tag = readTag();
        int valueLength = readLength();
        Asn1Header header = new Asn1Header(tag, valueLength,
            getValueBuffer(valueLength));
        return header;
    }

    protected abstract ByteBuffer getValueBuffer(int valueLength);

    protected abstract byte readByte() throws IOException;

    private Tag readTag() throws IOException {
        int tagFlags = readTagFlags();
        int tagNo = readTagNo(tagFlags);
        return new Tag(tagFlags, tagNo);
    }

    private int readTagFlags() throws IOException {
        int tagFlags = readByte() & 0xff;
        return tagFlags;
    }

    private int readTagNo(int tagFlags) throws IOException {
        int tagNo = tagFlags & 0x1f;

        if (tagNo == 0x1f) {
            tagNo = 0;

            int b = readByte() & 0xff;
            if ((b & 0x7f) == 0) {
                throw new IOException("Invalid high tag number found");
            }

            while (b >= 0 && (b & 0x80) != 0) {
                tagNo |= b & 0x7f;
                tagNo <<= 7;
                b = readByte();
            }

            tagNo |= b & 0x7f;
        }

        return tagNo;
    }

    private int readLength() throws IOException {
        int result = readByte() & 0xff;
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
                tmp = readByte() & 0xff;
                result = (result << 8) + tmp;
            }
        }

        if (result < 0) {
            throw new IOException("Invalid length " + result);
        }

        return result;
    }
}
