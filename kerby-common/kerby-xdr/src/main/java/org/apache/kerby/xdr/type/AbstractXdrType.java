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
 * The abstract XDR type for all the XDR types. It provides basic
 * encoding and decoding utilities.
 *
 * @param <T> the type of the value encoded/decoded or wrapped by this
 */
public abstract class AbstractXdrType<T> implements XdrType {
    private XdrDataType dataType;

    // The wrapped real value.
    private T value;

    /**
     * Default constructor.
     * @param dataType the dataType
     * @param value the value
     */
    public AbstractXdrType(XdrDataType dataType, T value) {
        this(dataType);
        this.value = value;
    }

    /**
     * Default constructor.
     * @param dataType the dataType
     */
    public AbstractXdrType(XdrDataType dataType) {
        this.dataType = dataType;
    }

    @Override
    public byte[] encode() throws IOException {
        int len = encodingLength();
        ByteBuffer byteBuffer = ByteBuffer.allocate(len);
        encode(byteBuffer);
        byteBuffer.flip();
        return byteBuffer.array();
    }

    @Override
    public void encode(ByteBuffer buffer) throws IOException {
        encodeBody(buffer);
    }

    protected abstract void encodeBody(ByteBuffer buffer) throws IOException;

    @Override
    public void decode(byte[] content) throws IOException {
        decode(ByteBuffer.wrap(content));
    }

    @Override
    public int encodingLength() throws IOException {
        return encodingBodyLength();
    }

    protected abstract int encodingBodyLength() throws IOException;

    @Override
    public void decode(ByteBuffer content) throws IOException {
    }

    public T getValue() {
        return value;
    }

    public void setValue(T value) {
        this.value = value;
    }

    public XdrDataType getDataType() {
        return dataType;
    }
}
