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
 * From RFC 4506 :
 *
 *         (MSB)                                                   (LSB)
 *       +-------+-------+-------+-------+-------+-------+-------+-------+
 *       |byte 0 |byte 1 |byte 2 |byte 3 |byte 4 |byte 5 |byte 6 |byte 7 |
 *       +-------+-------+-------+-------+-------+-------+-------+-------+
 *       <----------------------------64 bits---------------------------->
 *                                                  HYPER INTEGER
 *                                                  UNSIGNED HYPER INTEGER
 */
public class XdrLong extends XdrSimple<Long> {
    public XdrLong() {
        this((Long) null);
    }

    public XdrLong(Long value) {
        super(XdrDataType.LONG, value);
    }

    /**
     * The length of a signed long is 8.
     * @return Length of a signed long type.
     */
    @Override
    protected int encodingBodyLength() throws IOException {
        return 8;
    }

    /**
     * Encode Long type to bytes.
     * Cannot only use toByteArray() because of fixed 4 bytes length.
     */
    @Override
    protected void toBytes() throws IOException {
        long value = getValue().longValue();
        ByteBuffer buffer = ByteBuffer.allocate(8);
        buffer.putLong(value);
        buffer.flip();
        setBytes(buffer.array());
    }

    /**
     * Decode bytes to Long value.
     */
    @Override
    protected void toValue() {
        if (getBytes().length != 8) {
            byte[] longBytes = ByteBuffer.allocate(8).put(getBytes(), 0, 8).array();
            /**reset bytes in case the enum type is in a struct or union*/
            setBytes(longBytes);
        }
        ByteBuffer buffer = ByteBuffer.wrap(getBytes());
        setValue(buffer.getLong());
    }
}