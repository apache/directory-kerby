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

import org.apache.kerby.asn1.LimitedByteBuffer;
import org.apache.kerby.asn1.UniversalTag;

import java.io.IOException;

/**
 * ASN1 Boolean type
 */
public class Asn1Boolean extends Asn1Simple<Boolean> {
    private static final byte[] TRUE_BYTE = new byte[] {(byte) 0xff};
    private static final byte[] FALSE_BYTE = new byte[] {(byte) 0x00};

    public static final Asn1Boolean TRUE = new Asn1Boolean(true);
    public static final Asn1Boolean FALSE = new Asn1Boolean(false);

    /**
     * Default constructor, generally for decoding as a container
     */
    public Asn1Boolean() {
        this(null);
    }

    /**
     * Constructor with a value, generally for encoding of the value
     * @param value The boolean value
     */
    public Asn1Boolean(Boolean value) {
        super(UniversalTag.BOOLEAN, value);
    }

    @Override
    protected int encodingBodyLength() {
        return 1;
    }

    @Override
    protected void decodeBody(LimitedByteBuffer content) throws IOException {
        if (content.hasLeft() != 1) {
            throw new IOException("More than 1 byte found for Boolean");
        }
        super.decodeBody(content);
    }

    @Override
    protected void toBytes() {
        setBytes(getValue() ? TRUE_BYTE : FALSE_BYTE);
    }

    @Override
    protected void toValue() throws IOException {
        byte[] bytes = getBytes();
        if (bytes[0] == 0) {
            setValue(false);
        } else if ((bytes[0] & 0xff) == 0xff) {
            // DER only accepts 0xFF as true
            setValue(true);
        } else if (isBER()) {
            // BER accepts any non-zero as true
            setValue(true);
        } else {
            setValue(false);
        }
    }
}
