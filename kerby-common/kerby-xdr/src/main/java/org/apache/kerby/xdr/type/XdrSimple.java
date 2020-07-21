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
 * Xdr simple type, of single value other than complex type of multiple values.
 * Including: Bytes, Integer, Boolean, String.
 * Use toBytes() for encoding, toValue() for decoding.
 */
public abstract class XdrSimple<T> extends AbstractXdrType<T> {
    private byte[] bytes;

    /**
     * Default constructor, generally for decoding as a value container
     * @param dataTypeNo The dataType number
     */
    public XdrSimple(XdrDataType dataTypeNo) {
        this(dataTypeNo, null);
    }

    /**
     * Constructor with a value, generally for encoding of the value
     * @param xdrDataType The dataType number
     * @param value The value
     */
    public XdrSimple(XdrDataType xdrDataType, T value) {
        super(xdrDataType, value);
    }

    protected byte[] getBytes() {
        return bytes;
    }

    protected void setBytes(byte[] bytes) {
        if (bytes != null) {
            this.bytes = bytes.clone();
        } else {
            this.bytes = null;
        }
    }

    protected byte[] encodeBody() throws IOException {
        if (bytes == null) {
            /**Terminal step for encoding all the simple type to bytes.*/
            toBytes();
        }
        return bytes;
    }

    /**
     * Put encoded bytes into buffer.
     * @param buffer ByteBuffer to hold encoded bytes.
     */
    @Override
    protected void encodeBody(ByteBuffer buffer) throws IOException {
        byte[] body = encodeBody();
        if (body != null) {
            buffer.put(body);
        }
    }

    /**
     * Length including null bytes to maintain an multiple of 4.
     * @return The encoding body length
     */
    @Override
    protected int encodingBodyLength() throws IOException {
        if (getValue() == null) {
            return 0;
        }
        if (bytes == null) {
            /**Terminal step for decoding all the simple type to bytes.*/
            toBytes();
        }
        return bytes.length;
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        decodeBody(content);
    }

    protected void decodeBody(ByteBuffer body) throws IOException {
        byte[] result = body.array();
        if (result.length > 0) {
            setBytes(result);
            /**Terminal step for decoding all the bytes into simple types.*/
            toValue();
        }
    }

    /**
     * Decode bytes to simple value.
     */
    protected abstract void toValue() throws IOException;

    /**
     * Encode simple type to bytes.
     * @throws IOException e
     */
    protected abstract void toBytes() throws IOException;

    public static boolean isSimple(XdrDataType dataType) {
        switch (dataType) {
            case BOOLEAN:
            case INTEGER:
            case UNSIGNED_INTEGER:
            case ENUM:
            case STRING:
            case LONG:
                return true;
            default:
                return false;
        }
    }
}
