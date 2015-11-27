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
import org.apache.kerby.asn1.type.Asn1Type;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;

/**
 * Asn1 encoder
 */
public class Asn1OutputBuffer {
    private List<Asn1Type> objects;

    public Asn1OutputBuffer() {
        this.objects = new ArrayList<Asn1Type>(3);
    }

    public void write(Asn1Type value) {
        objects.add(value);
    }

    public ByteBuffer getOutput() {
        int len = encodingLength();
        ByteBuffer byteBuffer = ByteBuffer.allocate(len);
        encode(byteBuffer);
        return byteBuffer;
    }

    private int encodingLength() {
        int allLen = 0;
        for (Asn1Type item : objects) {
            if (item != null) {
                allLen += ((AbstractAsn1Type<?>) item).encodingLength();
            }
        }
        return allLen;
    }

    private void encode(ByteBuffer buffer) {
        for (Asn1Type item : objects) {
            if (item != null) {
                item.encode(buffer);
            }
        }
    }
}
