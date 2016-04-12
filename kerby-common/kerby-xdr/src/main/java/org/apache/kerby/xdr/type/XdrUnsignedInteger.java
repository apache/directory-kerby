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
package org.apache.kerby.xdr.type;

import org.apache.kerby.xdr.XdrDataType;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Xdr Unsigned Integer type from RFC 4506
 * An XDR unsigned integer is a 32-bit datum that encodes
 * a non-negative integer in the range [0,4294967295].
 * It is represented by an unsigned binary number whose most
 * and least significant bytes are 0 and 3, respectively.
 * An unsigned integer is declared as follows:
 * unsigned int identifier;
 *
 *      (MSB)                   (LSB)
 *      +-------+-------+-------+-------+
 *      |byte 0 |byte 1 |byte 2 |byte 3 |
 *      +-------+-------+-------+-------+
 *      <------------32 bits------------>
 */
public class XdrUnsignedInteger extends XdrSimple<Long> {
    public XdrUnsignedInteger() {
        this((Long) null);
    }

    public XdrUnsignedInteger(String value) {
        this(Long.valueOf(value));
    }

    public XdrUnsignedInteger(Long value) {
        super(XdrDataType.UNSIGNED_INTEGER, value);
    }

    /**
     * The length of an unsigned integer is 4.
     * @return Length of a unsigned integer type.
     */
    @Override
    protected int encodingBodyLength() {
        return 4; /**Length of XdrInteger is fixed as 4 bytes*/
    }

    /**
     * Encode Unsigned Integer type to bytes.
     */
    @Override
    protected void toBytes() throws IOException {
        Long value = getValue();
        validateUnsignedInteger(value); /**Check whether the long value is valid unsigned int*/
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(value);
        byte[] bytes = new byte[4]; /**The encoding length is 4*/
        System.arraycopy(buffer.array(), 4, bytes, 0, 4);
        setBytes(bytes);
    }

    private void validateUnsignedInteger(Long value) throws IOException {
        if (value < 0 || value > 4294967295L) {
            throw new IOException("Invalid unsigned integer: " + value);
        }
    }

    /**
     * Decode bytes to Unsigned Integer value.
     */
    @Override
    protected void toValue() {
        if (getBytes().length != 4) {
            byte[] bytes = ByteBuffer.allocate(4).put(getBytes(), 0, 4).array();
            setBytes(bytes); /**reset bytes in case the enum type is in a struct or union*/
        }

        byte[] longBytes = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
                (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        System.arraycopy(getBytes(), 0, longBytes, 4, 4);
        ByteBuffer buffer = ByteBuffer.wrap(longBytes);
        setValue(buffer.getLong());
    }
}
