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

/*
 *  From RFC 4506 :
 *
 *           0     1     2     3     4     5   ...
 *        +-----+-----+-----+-----+-----+-----+...+-----+-----+...+-----+
 *        |        length n       |byte0|byte1|...| n-1 |  0  |...|  0  |
 *        +-----+-----+-----+-----+-----+-----+...+-----+-----+...+-----+
 *        |<-------4 bytes------->|<------n bytes------>|<---r bytes--->|
 *                                |<----n+r (where (n+r) mod 4 = 0)---->|
 *                                                 VARIABLE-LENGTH OPAQUE
 */

public class XdrBytes extends XdrSimple<byte[]> {
    private int padding;

    public XdrBytes() {
        this(null);
    }

    public XdrBytes(byte[] value) {
        super(XdrDataType.BYTES, value);
    }

    @Override
    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        byte[] header = new byte[4];
        System.arraycopy(bytes, 0, header, 0, 4);
        int byteArrayLen = ByteBuffer.wrap(header).getInt();
        int paddingBytes = (4 - (byteArrayLen % 4)) % 4;
        validatePaddingBytes(paddingBytes);
        setPadding(paddingBytes);
        
        if (bytes.length != byteArrayLen + 4 + paddingBytes) {
            int totalLength = byteArrayLen + 4 + paddingBytes;
            byte[] resetBytes = ByteBuffer.allocate(totalLength)
                    .put(getBytes(), 0, totalLength).array();
            /**reset bytes in case the enum type is in a struct or union*/
            setBytes(resetBytes);
        }
        
        byte[] content = new byte[byteArrayLen];
        if (bytes.length > 1) {
            System.arraycopy(bytes, 4, content, 0, byteArrayLen);
        }
        setValue(content);
    }

    @Override
    protected int encodingBodyLength() throws IOException {
        if (getValue() != null) {
            padding = (4 - getValue().length % 4) % 4;
            return getValue().length + padding + 4;
        }
        return 0;
    }

    @Override
    protected void toBytes() throws IOException {
        if (getValue() != null) {
            byte[] bytes = new byte[encodingBodyLength()];
            int length = getValue().length;
            bytes[0] = (byte) (length >> 24);
            bytes[1] = (byte) (length >> 16);
            bytes[2] = (byte) (length >> 8);
            bytes[3] = (byte) (length);
            System.arraycopy(getValue(), 0, bytes, 4, length);
            setBytes(bytes);
        }
    }

    public void setPadding(int padding) {
        this.padding = padding;
    }

    public int getPadding() {
        return padding;
    }

    private void validatePaddingBytes(int paddingBytes) throws IOException {
        if (paddingBytes < 0 || paddingBytes > 3) {
            throw new IOException("Bad padding number: " + paddingBytes + ", should be in [0, 3]");
        }
    }
}
