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

import org.apache.kerby.asn1.type.Asn1Object;
import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Asn1 decoder. Given an input stream, it validates and parses
 * according to ASN1 spec, and the resultant object can be read
 * and read until exhausted.
 */
public class Asn1InputBuffer {
    private final ByteBuffer buffer;

    /**
     * Constructor with bytes.
     * @param bytes The bytes
     */
    public Asn1InputBuffer(byte[] bytes) {
        this(ByteBuffer.wrap(bytes));
    }

    /**
     * Constructor with a ByteBuffer.
     * @param byteBuffer The byte buffer
     */
    public Asn1InputBuffer(ByteBuffer byteBuffer) {
        this.buffer = byteBuffer;
    }

    /**
     * Parse and read ASN1 object from the stream. If it's already
     * exhausted then null will be returned to indicate the end.
     * @return an ASN1 object if available otherwise null
     * @throws IOException e
     */
    public Asn1Type read() throws IOException {
        Asn1Type one = Asn1Object.readOne(buffer);
        return one;
    }
}
