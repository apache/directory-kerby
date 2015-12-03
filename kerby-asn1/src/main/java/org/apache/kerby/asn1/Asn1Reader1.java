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

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * ASN1 reader for stateful reading.
 */
public final class Asn1Reader1 extends Asn1Reader {

    public Asn1Reader1(ByteBuffer buffer) {
        super(buffer);
    }

    @Override
    protected byte readByte() throws IOException {
        return buffer.get();
    }

    @Override
    protected ByteBuffer getValueBuffer(int valueLength) {
        ByteBuffer result = buffer.duplicate();
        result.limit(buffer.position() + valueLength);
        buffer.position(buffer.position() + valueLength);

        return result;
    }
}
