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

import org.apache.kerby.asn1.type.AbstractAsn1Type;
import org.apache.kerby.asn1.type.Asn1Item;
import org.apache.kerby.asn1.type.Asn1Type;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Asn1 decoder
 */
public class Asn1InputBuffer {
    private final LimitedByteBuffer limitedBuffer;

    public Asn1InputBuffer(byte[] bytes) {
        this(new LimitedByteBuffer(bytes));
    }

    public Asn1InputBuffer(ByteBuffer byteBuffer) {
        this(new LimitedByteBuffer(byteBuffer));
    }

    public Asn1InputBuffer(LimitedByteBuffer limitedByteBuffer) {
        this.limitedBuffer = limitedByteBuffer;
    }

    public Asn1Type read() throws IOException {
        if (! limitedBuffer.available()) {
            return null;
        }
        Asn1Item one = AbstractAsn1Type.decodeOne(limitedBuffer);
        if (one.isSimple()) {
            one.decodeValueAsSimple();
        } else if (one.isCollection()) {
            one.decodeValueAsCollection();
        }
        if (one.isFullyDecoded()) {
            return one.getValue();
        }
        return one;
    }

    public void readBytes(byte[] bytes) throws IOException {
        limitedBuffer.readBytes(bytes);
    }

    public byte[] readAllLeftBytes() throws IOException {
        return limitedBuffer.readAllLeftBytes();
    }

    public void skipNext() throws IOException {
        if (limitedBuffer.available()) {
            AbstractAsn1Type.skipOne(limitedBuffer);
        }
    }

    public void skipBytes(int len) throws IOException {
        if (limitedBuffer.available()) {
            limitedBuffer.skip(len);
        }
    }
}
