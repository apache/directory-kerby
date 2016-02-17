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
import java.nio.ByteBuffer;

/**
 * Xdr Integer type from RFC 4506
 * An XDR signed integer is a 32-bit datum
 * that encodes an integer in the range [-2147483648,2147483647].
 * The integer is represented in two's complement notation.
 * The most and least significant bytes are0 and 3, respectively.
 * Integers are declared as follows:
 * int identifier;
 *
 *      (MSB)                   (LSB)
 *      +-------+-------+-------+-------+
 *      |byte 0 |byte 1 |byte 2 |byte 3 |
 *      +-------+-------+-------+-------+
 *      <------------32 bits------------>
 */
public class XdrInteger extends XdrSimple<Integer> {
    public XdrInteger() {
        this((Integer) null);
    }

    public XdrInteger(Integer value) {
        super(XdrDataType.INTEGER, value);
    }

    /**
     * The length of a signed integer is 4.
     * @return Length of a signed integer type.
     */
    @Override
    protected int encodingBodyLength() {
        return 4; /**Length of XdrInteger is fixed as 4 bytes*/
    }

    /**
     * Encode Integer type to bytes.
     * Cannot only use toByteArray() because of fixed 4 bytes length.
     */
    @Override
    protected void toBytes() {
        int value = getValue().intValue();
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(value);
        buffer.flip();
        setBytes(buffer.array());
    }

    /**
     * Decode bytes to Integer value.
     */
    @Override
    protected void toValue() {
        if (getBytes().length != 4) {
            byte[] intBytes = ByteBuffer.allocate(4).put(getBytes(), 0, 4).array();
            setBytes(intBytes); /**reset bytes in case the enum type is in a struct or union*/
        }
        ByteBuffer buffer = ByteBuffer.wrap(getBytes());
        setValue(buffer.getInt());
    }

}
