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
 * ASN1 simple type, of single value other than complex type of multiple values.
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
        this.bytes = bytes;
    }

    protected byte[] encodeBody() {
        if (bytes == null) {
            toBytes();
        }
        return bytes;
    }

    @Override
    protected  void encodeHead(ByteBuffer buffer) {
        byte[] head = headToByte();
        if (head != null) {
            buffer.put(head);
        }
    }

    protected byte[] headToByte() {
        return null;
    }

    @Override
    protected void encodeBody(ByteBuffer buffer) {
        byte[] body = encodeBody();
        if (body != null) {
            buffer.put(body);
        }
    }

    @Override
    protected int encodingBodyLength() {
        if (getValue() == null) {
            return 0;
        }
        if (bytes == null) {
            toBytes();
        }
        return bytes.length;
    }

    @Override
    public void decode(ByteBuffer content) throws IOException {
        ByteBuffer body = decodeHead(content);
        decodeBody(body);
    }

    protected ByteBuffer decodeHead(ByteBuffer content) {
        return content;
    }

    protected void decodeBody(ByteBuffer body) {
        byte[] result = body.array();
        if (result.length > 0) {
            setBytes(result);
            toValue();
        }
    }

    protected void toValue() { }

    protected void toBytes() { }

    public static boolean isSimple(XdrDataType dataType) {
        switch (dataType) {
            case BOOLEAN:
            case INTEGER:
            case STRING:
                return true;
            default:
                return false;
        }
    }
}
