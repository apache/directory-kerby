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
package org.apache.kerby.asn1.type;

import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;

public class Asn1BitString extends Asn1Simple<byte[]> {
    private int padding;

    public Asn1BitString() {
        this(null);
    }

    public Asn1BitString(byte[] value) {
        this(value, 0);
    }

    public Asn1BitString(byte[] value, int padding) {
        super(UniversalTag.BIT_STRING, value);
        this.padding = padding;
    }

    public void setPadding(int padding) {
        this.padding = padding;
    }

    public int getPadding() {
        return padding;
    }

    @Override
    protected int encodingBodyLength() {
        return getValue().length + 1;
    }

    @Override
    protected void toBytes() {
        byte[] bytes = new byte[encodingBodyLength()];
        bytes[0] = (byte) padding;
        System.arraycopy(getValue(), 0, bytes, 1, bytes.length - 1);
        setBytes(bytes);
    }

    @Override
    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        if (bytes.length < 1) {
            throw new IOException("Bad stream, zero bytes found for bitstring");
        }
        int paddingBits = bytes[0];
        validatePaddingBits(paddingBits);
        setPadding(paddingBits);

        byte[] newBytes = new byte[bytes.length - 1];
        if (bytes.length > 1) {
            System.arraycopy(bytes, 1, newBytes, 0, bytes.length - 1);
        }
        setValue(newBytes);
    }

    private void validatePaddingBits(int paddingBits) throws IOException {
        if (paddingBits < 0 || paddingBits > 7) {
            throw new IOException("Bad padding number: " + paddingBits + ", should be in [0, 7]");
        }
    }
}
