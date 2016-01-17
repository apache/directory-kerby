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

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * The ASN1 type interface for all ASN1 types.
 */
public interface XdrType {

    /**
     * Get length of encoding bytes by just calculating without real encoding.
     * Generally it's called to prepare for the encoding buffer.
     * @return length of encoding bytes
     */
    int encodingLength() throws IOException;

    /**
     * Encode the type, by recursively.
     * @return encoded bytes
     */
    byte[] encode() throws IOException;

    /**
     * Encode the type, by recursively, using the provided buffer.
     * @param buffer The byte buffer
     */
    void encode(ByteBuffer buffer) throws IOException;

    /**
     * Decode the content bytes into this type.
     * @param content The content bytes
     * @throws IOException e
     */
    void decode(byte[] content) throws IOException;

    /**
     * Decode the content bytes into this type.
     * @param content The content bytes
     * @throws IOException e
     */
    void decode(ByteBuffer content) throws IOException;
}
